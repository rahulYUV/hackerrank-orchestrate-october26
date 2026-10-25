#!/usr/bin/env python3
"""Parse participant-facing text evidence into a SQLite observations table.

PDF and PNG artifacts are intentionally skipped in this investigation phase.
Run from any directory with:
    py code/parse_evidence.py [--output code/observations.sqlite]
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import sqlite3
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = ROOT / "dataset" / "evidence"
MANIFEST = ROOT / "dataset" / "evidence_files.csv"
SUPPORTED = {".sql", ".log", ".json", ".txt", ".pdf", ".png"}
SKIPPED: set[str] = set()

TIME_KEYS = (
    "captured_at", "recorded_at", "event_at", "created_at", "updated_at",
    "occurred_at", "timestamp", "snapshot_at", "exported_at", "time",
)
SYSTEM_KEYS = ("system_id", "system", "data_store", "origin_system", "service", "service_name")
RESOURCE_KEYS = ("resource_id", "record_id", "object_id", "profile_id", "id")
CATEGORY_KEYS = ("category", "data_category", "record_type", "collection", "collection_name", "table_name", "event_name", "event", "type")
STATE_KEYS = ("state", "record_state", "status", "result", "account_status", "disposition", "outcome", "action")


def first_value(row: dict[str, Any], keys: Iterable[str]) -> Any:
    lowered = {str(k).lower(): v for k, v in row.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if value is not None and str(value).strip():
            return value
    return None


def normalize(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def table_system(table: str) -> str:
    name = table.lower()
    rules = (
        (("analytics", "telemetry"), "analytics_platform"),
        (("search", "index"), "search_service"),
        (("support", "ticket", "message", "attachment"), "support_platform"),
        (("export",), "export_service"),
        (("backup", "archive"), "backup_service"),
        (("connector", "flow", "integration"), "integration_service"),
        (("audit", "security"), "security_service"),
        (("tombstone", "deleted_customer_reference", "identity"), "identity_service"),
        (("account", "profile", "customer_profiles"), "account_service"),
        (("email", "delivery", "notification"), "notification_service"),
        (("order", "payment", "legal", "retention"), "commerce_service"),
    )
    for fragments, system in rules:
        if any(fragment in name for fragment in fragments):
            return system
    return table


def record_payload(row: dict[str, Any]) -> str:
    # Preserve the complete participant-visible record for later identity matching.
    return json.dumps(row, ensure_ascii=False, sort_keys=True, default=str)


def bool_value(value: Any) -> bool | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "enabled", "active", "allowed"}:
        return True
    if text in {"0", "false", "no", "off", "disabled", "inactive", "blocked", "denied"}:
        return False
    return None


def normalized_state(row: dict[str, Any]) -> str:
    """Map source status fields into the common state vocabulary when possible."""
    lowered = {str(k).lower(): v for k, v in row.items()}
    resource = normalize(first_value(row, RESOURCE_KEYS)).lower()
    category = normalize(first_value(row, CATEGORY_KEYS)).lower()

    if "analytics" in category or "telemetry" in category:
        direct_fields = ("name", "full_name", "email", "phone", "email_hash", "email_sha256", "customer_reference")
        present_direct_fields = [key for key in direct_fields if key in lowered]
        if present_direct_fields and all(normalize(lowered[key]).lower() in {"", "null", "none"} for key in present_direct_fields):
            return "ANONYMIZED"

    if "tombstone" in category or "deleted_customer_reference" in category or resource.startswith("tombstone_"):
        direct_fields = ("name", "full_name", "email", "phone", "email_hash", "email_sha256")
        if any(normalize(lowered.get(key)).lower() not in {"", "null", "none"} for key in direct_fields):
            return "IDENTIFIABLE"
        return "REDACTED"

    direct_identifiers = lowered.get("direct_identifiers")
    if direct_identifiers is not None:
        try:
            return "ANONYMIZED" if int(direct_identifiers) == 0 else "IDENTIFIABLE"
        except (TypeError, ValueError):
            pass

    try:
        if "rows" in lowered and int(lowered["rows"]) == 0:
            return "ABSENT"
    except (TypeError, ValueError):
        pass
    try:
        if int(lowered.get("http_status", 0)) == 404:
            return "ABSENT"
    except (TypeError, ValueError):
        pass

    raw = normalize(first_value(row, STATE_KEYS)).upper().replace("-", "_").replace(" ", "_")
    if raw in {"NOT_FOUND", "NOTFOUND", "NOT_PRESENT", "MISSING", "ABSENT", "DELETED"}:
        return "ABSENT"

    restore_allowed = bool_value(lowered.get("restore_allowed"))
    if restore_allowed is not None:
        return "ACTIVE" if restore_allowed else "BLOCKED"
    enabled = bool_value(lowered.get("enabled"))
    if enabled is not None:
        return "ACTIVE" if enabled else "DISABLED"
    deletion_block = bool_value(lowered.get("deletion_block"))
    if deletion_block is True:
        return "BLOCKED"
    eligible = bool_value(lowered.get("eligible"))
    if eligible is not None:
        return "ACTIVE" if eligible and deletion_block is not True else "BLOCKED"
    archive_present = bool_value(lowered.get("archive_present"))
    if archive_present is not None:
        return "PRESENT" if archive_present else "ABSENT"

    aliases = {
        "FOUND": "PRESENT", "HIT": "PRESENT", "EXISTS": "PRESENT", "PRESENT": "PRESENT",
        "DELETION_PENDING": "PRESENT",
        "ACTIVE": "ACTIVE" if any(word in category for word in ("flow", "connector", "subscription", "restore", "backup")) else "PRESENT",
        "DISABLED": "DISABLED", "INACTIVE": "DISABLED",
        "BLOCKED": "BLOCKED", "RESTORE_BLOCKED": "BLOCKED",
        "ANONYMIZED": "ANONYMIZED", "REDACTED": "REDACTED",
        "IDENTIFIABLE": "IDENTIFIABLE", "ABSENT": "ABSENT",
    }
    if raw in aliases:
        return aliases[raw]

    try:
        if int(lowered.get("rows", -1)) > 0:
            return "PRESENT"
    except (TypeError, ValueError):
        pass
    try:
        code = int(lowered.get("http_status", 0))
        if 200 <= code < 300:
            return "PRESENT"
    except (TypeError, ValueError):
        pass
    return raw or "PRESENT"


def add_observation(db: sqlite3.Connection, evidence_id: str, captured_at: str,
                    system_id: str, resource_id: str, category: str,
                    state: str, normalized: str, identifiers: str) -> None:
    db.execute(
        """INSERT INTO observations
           (evidence_id, captured_at, system_id, resource_id, category, state, normalized_state, identifiers)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (evidence_id, captured_at, system_id, resource_id, category, state, normalized, identifiers),
    )


def parse_json(db: sqlite3.Connection, evidence_id: str, path: Path, file_time: str) -> int:
    root = json.loads(path.read_text(encoding="utf-8-sig"))
    count = 0

    def walk(node: Any, context: dict[str, Any]) -> None:
        nonlocal count
        if isinstance(node, dict):
            merged = {**context, **node}
            resource = first_value(node, RESOURCE_KEYS)
            if resource is not None:
                timestamp = first_value(merged, TIME_KEYS) or file_time
                system = first_value(merged, SYSTEM_KEYS) or ""
                category = first_value(merged, CATEGORY_KEYS) or ""
                state = first_value(merged, STATE_KEYS) or ""
                add_observation(db, evidence_id, normalize(timestamp), normalize(system),
                                normalize(resource), normalize(category), normalize(state), normalized_state(merged),
                                record_payload(node))
                count += 1
            elif node.get("records") == []:
                # Preserve an explicit empty snapshot scope; it can ground absence
                # when the caller knows the target resource from other evidence.
                timestamp = first_value(merged, TIME_KEYS) or file_time
                system = first_value(merged, SYSTEM_KEYS) or ""
                category = first_value(merged, CATEGORY_KEYS) or ""
                if system or category:
                    add_observation(db, evidence_id, normalize(timestamp), normalize(system), "",
                                    normalize(category), "rows=0", "ABSENT",
                                    record_payload({"snapshot_scope": merged, "records": []}))
                    count += 1
            # Inherit snapshot metadata into nested record objects.
            child_context = {
                key: value for key, value in merged.items()
                if key.lower() in {"captured_at", "snapshot_at", "exported_at", "system", "system_id", "data_store", "collection"}
            }
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    nested_context = dict(child_context)
                    if normalize(key).casefold() in {
                        "account_service", "analytics_platform", "search_service", "support_platform",
                        "export_service", "backup_service", "integration_service", "security_service",
                        "identity_service", "notification_service", "commerce_service",
                    }:
                        nested_context["system_id"] = key
                    walk(value, nested_context)
        elif isinstance(node, list):
            for value in node:
                walk(value, context)

    walk(root, {})
    return count


KV_RE = re.compile(r'([A-Za-z_][\w.-]*)=("(?:\\.|[^"\\])*"|[^\s]+)')
BRACKET_LOG_RE = re.compile(r"^(\S+)\s+\[([^]]+)\]\s+\[([^]]+)\](?:\s+\[([^]]+)\])?\s+([^:]+):\s*(.*)$")


def parse_key_values(text: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for match in KV_RE.finditer(text):
        key, token = match.groups()
        if token.startswith('"'):
            try:
                value = json.loads(token)
            except json.JSONDecodeError:
                value = token[1:-1]
        else:
            value = token
        attrs[key] = str(value)
    return attrs


def parse_log(db: sqlite3.Connection, evidence_id: str, path: Path, file_time: str) -> int:
    identity_keys = {
        "subject_key", "subject_ref", "lookup_key", "correlation_key", "customer_email",
        "customer_reference", "user_id", "email", "phone", "email_hash", "email_sha256",
    }
    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        stripped = line.strip()
        bracketed = BRACKET_LOG_RE.match(stripped)
        parts = stripped.split(None, 1)
        timestamp = parts[0] if parts else file_time
        if bracketed:
            timestamp, level, service, trace_id, event, tail = bracketed.groups()
            header = {"level": level, "service": service, "trace_id": trace_id or "", "event": event.strip()}
            fields = parse_key_values(tail)
        elif len(parts) == 2 and parts[1].startswith("<"):
            # RFC5424-like stream: timestamp <PRI>version host app procid msgid sd message
            syslog_parts = parts[1].split(None, 6)
            if len(syslog_parts) < 6:
                continue
            header = {
                "syslog_pri_version": syslog_parts[0], "host": syslog_parts[1],
                "service": syslog_parts[2], "trace_id": syslog_parts[3],
                "message_id": syslog_parts[4], "structured_data": syslog_parts[5],
            }
            fields = parse_key_values(syslog_parts[6]) if len(syslog_parts) > 6 else {}
        elif " | " in stripped:
            # Operations stream: timestamp | level | service | trace | event | key=value...
            columns = [item.strip() for item in stripped.split("|", 5)]
            if len(columns) < 5:
                continue
            timestamp, level, service, trace_id, event = columns[:5]
            header = {"level": level, "service": service, "trace_id": trace_id, "event": event}
            fields = parse_key_values(columns[5]) if len(columns) > 5 else {}
        elif len(parts) == 2:
            payload = parts[1]
            if payload.startswith("{"):
                header = json.loads(payload)
            else:
                # Level-first service logs and key/value readback logs share the same parser.
                header = parse_key_values(payload)
            fields = {}
            # Older collector logs encode a second key/value payload inside message.
            if header.get("message"):
                fields = parse_key_values(header["message"])
        else:
            continue
        attrs = {**header, **fields}
        event = normalize(first_value(attrs, ("event", "event_name", "operation", "message_id"))).casefold()
        # Request/trace identifiers vary between log dialects. correlation_key is
        # an identity field in this corpus, so it is deliberately not a group key.
        trace_id = first_value(attrs, ("trace_id", "requestId", "request_id", "requestid", "correlation_id"))
        service = first_value(attrs, ("system_id", "system", "data_store", "origin_system", "service", "service_name", "function")) or ""
        entries.append({"timestamp": timestamp or file_time, "header": header, "fields": fields,
                        "attrs": attrs, "event": event,
                        "trace_key": (normalize(service).casefold(), normalize(trace_id).casefold()) if trace_id else None})

    # First collect identity values for each trace so a later resource read can
    # inherit subject_key/subject_ref/lookup_key values from an earlier start.
    trace_identities: dict[tuple[str, str], dict[str, list[str]]] = {}
    for entry in entries:
        key = entry["trace_key"]
        if not key:
            continue
        identity = trace_identities.setdefault(key, {})
        for name, value in entry["attrs"].items():
            field = str(name).casefold()
            text = normalize(value)
            if field in identity_keys and text and text.casefold() not in {"null", "none", "unknown", "n/a"}:
                values = identity.setdefault(field, [])
                if text not in values:
                    values.append(text)

    count = 0
    for entry in entries:
        attrs = entry["attrs"]
        event = entry["event"]
        # *_started rows may carry subject identity, but never represent a
        # completed resource state and must not create an observation.
        if event.endswith("_started"):
            continue
        resource = first_value(attrs, RESOURCE_KEYS)
        if not resource:
            continue
        system = first_value(attrs, ("system_id", "system", "data_store", "origin_system", "service", "service_name", "function")) or ""
        category = first_value(attrs, ("category", "data_category", "record_type", "collection", "collection_name", "event_name", "event", "operation")) or ""
        state = first_value(attrs, STATE_KEYS) or ""
        merged_identity = trace_identities.get(entry["trace_key"], {}) if entry["trace_key"] else {}
        payload = {**merged_identity, "trace_identity": merged_identity,
                   "header": entry["header"], "fields": entry["fields"], **attrs}
        add_observation(db, evidence_id, entry["timestamp"], normalize(system),
                        normalize(resource), normalize(category), normalize(state),
                        normalized_state(attrs), record_payload(payload))
        count += 1
    return count


def parse_text(db: sqlite3.Connection, evidence_id: str, path: Path, file_time: str) -> int:
    count = 0
    # The handover file uses: timestamp | system | resource | category | state | identifier.
    pattern = re.compile(r"^\s*-\s*(\S+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*(.*?)\s*$")
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        match = pattern.match(line)
        if not match:
            continue
        timestamp, system, resource, category, state, identifier = (part.strip() for part in match.groups())
        add_observation(db, evidence_id, timestamp or file_time, system, resource,
                        category, state, normalized_state({"category": category, "state": state}),
                        record_payload({"captured_at": timestamp, "system_id": system,
                                        "resource_id": resource, "category": category,
                                        "state": state, "subject_reference": identifier}))
        count += 1
    return count


def parse_pdf(db: sqlite3.Connection, evidence_id: str, path: Path, file_time: str,
              origin: str = "") -> int:
    """Extract searchable PDF text with pypdf and emit resource-level observations."""
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise RuntimeError("PDF parsing requires pypdf; install code/requirements.txt") from exc

    pages = [(page.extract_text() or "") for page in PdfReader(str(path)).pages]
    full_text = "\n".join(pages)
    count = 0
    common = {"page_count": len(pages), "origin": origin,
              "source_path": path.relative_to(ROOT).as_posix()}
    text_lines = full_text.splitlines()

    def local_context(resource_id: str) -> str:
        hits = [i for i, line in enumerate(text_lines) if resource_id.casefold() in line.casefold()]
        return "\n".join("\n".join(text_lines[max(0, i - 1):min(len(text_lines), i + 2)]) for i in hits)

    # Extract IDs whose system and policy category are established by their prefix
    # and surrounding document type. Avoid treating order numbers as deletion IDs
    # except in the explicit retention register.
    typed_patterns = (
        (r"\baccount_\d+\b", "account_service", "USER_PROFILE"),
        (r"\bsearch_\d+\b", "search_service", "SEARCH_INDEX_ENTRY"),
        (r"\bsupport_\d+\b", "support_platform", "SUPPORT_ATTACHMENT"),
        (r"\banalytics_\d+\b", "analytics_platform", "ANALYTICS_PROFILE"),
        (r"\bexport_\d+\b", "export_service", "USER_EXPORT"),
        (r"\bbackup_\d+\b", "backup_service", "BACKUP_ARCHIVE"),
        (r"\bdata_flow_\d+\b", "integration_service", "DATA_FLOW"),
        (r"\baudit_record_\d+\b", "security_service", "SECURITY_AUDIT_LOG"),
        (r"\btombstone_\d+\b", "identity_service", "ACCOUNT_TOMBSTONE"),
    )
    resources: dict[str, tuple[str, str]] = {}
    for pattern, system, category in typed_patterns:
        for resource_id in re.findall(pattern, full_text, flags=re.IGNORECASE):
            resources[resource_id] = (system, category)

    if "retention register" in full_text.casefold() or "disputed orders" in full_text.casefold():
        for resource_id, user_id in re.findall(r"\b(ORD-\d+)\s*\|\s*(user_\d+)\b", full_text, flags=re.IGNORECASE):
            resources[resource_id] = ("legal_service", "LEGAL_HOLD_RECORD")
            payload = {**common, "pdf_context": local_context(resource_id),
                       "resource_id": resource_id, "user_id": user_id,
                       "category": "LEGAL_HOLD_RECORD"}
            add_observation(db, evidence_id, file_time, "legal_service", resource_id,
                            "LEGAL_HOLD_RECORD", "PRESENT", "PRESENT", record_payload(payload))
            count += 1

    for resource_id, (system, category) in sorted(resources.items()):
        payload = {**common, "pdf_context": local_context(resource_id),
                   # Keep document text available to the identity matcher: names,
                   # emails, and phones can appear elsewhere on the same page(s)
                   # than the typed resource reference.
                   "pdf_text": full_text,
                   "resource_id": resource_id, "category": category,
                   "extracted_resource_id": resource_id}
        add_observation(db, evidence_id, file_time, system, resource_id, category,
                        "PRESENT", "PRESENT", record_payload(payload))
        count += 1

    if not resources:
        # Keep text-only identity evidence available for matching without inventing
        # a record identifier that is not present in the document.
        system = (origin.replace(" ", "_") or "document_service")
        payload = {**common, "pdf_text": full_text, "category": "DOCUMENT_TEXT", "resource_id": ""}
        add_observation(db, evidence_id, file_time, system, "", "DOCUMENT_TEXT",
                        "PRESENT", "PRESENT", record_payload(payload))
        count += 1
    return count


OCR_RESOURCE_TYPES = (
    ("account_", "account_service", "USER_PROFILE"),
    ("search_", "search_service", "SEARCH_INDEX_ENTRY"),
    ("support_", "support_platform", "SUPPORT_ATTACHMENT"),
    ("analytics_", "analytics_platform", "ANALYTICS_PROFILE"),
    ("export_", "export_service", "USER_EXPORT"),
    ("data_flow_", "integration_service", "DATA_FLOW"),
    ("backup_", "backup_service", "BACKUP_ARCHIVE"),
    ("audit_record_", "security_service", "SECURITY_AUDIT_LOG"),
    ("tombstone_", "identity_service", "ACCOUNT_TOMBSTONE"),
    ("marketing_", "marketing_platform", "MARKETING_PROFILE"),
    ("object_", "object_storage", "SUPPORT_ATTACHMENT"),
)
OCR_RESOURCE_RE = re.compile(r"\b(?:" + "|".join(re.escape(x[0]) for x in OCR_RESOURCE_TYPES) + r")\d+\b", re.I)


def tesseract_executable() -> str | None:
    """Prefer the configured executable, then the documented default, then PATH."""
    configured = os.environ.get("TESSERACT_CMD", "").strip().strip('"')
    default = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    for candidate in (configured, default):
        if candidate and Path(candidate).is_file():
            return candidate
    return shutil.which("tesseract")


def read_catalog_owners() -> dict[tuple[str, str], list[dict[str, str]]]:
    owners: dict[tuple[str, str], list[dict[str, str]]] = {}
    with (ROOT / "dataset" / "system_activity.csv").open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            if (normalize(row.get("event_type")).upper() != "LINK_RESOURCE_IDENTITY" or
                    normalize(row.get("source_system")).casefold() != "data_catalog"):
                continue
            details = normalize(row.get("details"))
            email = re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", details)
            user_id = re.search(r"\buser_\d+\b", details, flags=re.I)
            owners.setdefault((normalize(row.get("target_system")), normalize(row.get("resource_id"))), []).append(
                {"email": email.group(0) if email else "", "user_id": user_id.group(0) if user_id else "",
                 "details": details})
    return owners


def read_identity_tokens() -> dict[str, str]:
    """Map participant-visible current and historical identity values to stable user IDs."""
    result: dict[str, str] = {}
    paths = (ROOT / "dataset" / "user_identities.csv", ROOT / "dataset" / "user_audit_log.csv")
    for path in paths:
        with path.open(encoding="utf-8-sig", newline="") as stream:
            for row in csv.DictReader(stream):
                uid = normalize(row.get("user_id"))
                if not uid:
                    continue
                result[uid.casefold()] = uid
                fields = ("name", "full_name", "email", "phone", "email_hash")
                if path.name == "user_audit_log.csv":
                    field = normalize(row.get("field_name")).casefold()
                    if field not in {"name", "full_name", "email", "phone", "email_hash", "email_sha256"}:
                        continue
                    fields = ("old_value", "new_value")
                for key in fields:
                    value = normalize(row.get(key))
                    if value:
                        result[value.casefold()] = uid
    return result


def read_identity_names() -> dict[str, str]:
    with (ROOT / "dataset" / "user_identities.csv").open(encoding="utf-8-sig", newline="") as stream:
        return {normalize(row.get("user_id")): normalize(row.get("name"))
                for row in csv.DictReader(stream) if normalize(row.get("user_id")) and normalize(row.get("name"))}


def ocr_state(resource_id: str, context: str) -> tuple[str, str]:
    folded = context.casefold()
    rid = resource_id.casefold()
    if rid.startswith("tombstone_"):
        direct = re.search(r"\b(name|email|phone|email hash|email_sha256)\b\s*[:=]\s*(?!null\b|none\b|—|-)\S+", context, re.I)
        return ("IDENTIFIABLE", "IDENTIFIABLE") if direct else ("REDACTED", "REDACTED") if "retained reference" in folded else ("PRESENT", "PRESENT")
    if rid.startswith("data_flow_"):
        if re.search(r"\b(disabled|inactive|paused|stopped)\b", folded):
            return "DISABLED", "DISABLED"
        if re.search(r"\b(active|enabled|continuous|healthy|running)\b", folded):
            return "ACTIVE", "ACTIVE"
    if rid.startswith("backup_"):
        if re.search(r"\b(restore blocked|blocked|disabled|not restorable)\b", folded):
            return "BLOCKED", "BLOCKED"
        if re.search(r"\b(restore allowed|restorable|restore enabled|active)\b", folded):
            return "ACTIVE", "ACTIVE"
    if rid.startswith("audit_record_"):
        return "PRESENT", "PRESENT"
    if re.search(r"\b(live profile|live|active|present|exists|ready)\b", folded):
        return "PRESENT", "PRESENT"
    if re.search(r"\b(anonymized|anonymous)\b", folded):
        return "ANONYMIZED", "ANONYMIZED"
    if re.search(r"\b(redacted|removed identifiers)\b", folded):
        return "REDACTED", "REDACTED"
    return "PRESENT", "PRESENT"


def parse_png(db: sqlite3.Connection, evidence_id: str, path: Path, file_time: str,
              owners: dict[tuple[str, str], list[dict[str, str]]], identity_tokens: dict[str, str],
              identity_names: dict[str, str], tesseract: str | None) -> tuple[int, list[str]]:
    """OCR a screenshot and keep only resource IDs with grounded ownership links."""
    if not tesseract:
        return 0, []
    result = subprocess.run([tesseract, str(path), "stdout", "--psm", "6"],
                            capture_output=True, text=True, encoding="utf-8", errors="replace",
                            timeout=45, check=False)
    text = result.stdout.strip()
    db.execute("INSERT OR REPLACE INTO image_ocr (evidence_id, captured_at, ocr_text) VALUES (?, ?, ?)",
               (evidence_id, file_time, text))
    if result.returncode != 0 or not text:
        return 0, []
    lines = text.splitlines()
    all_resource_ids = {m.group(0).casefold() for m in OCR_RESOURCE_RE.finditer(text)}
    rows: dict[str, tuple[str, str, str, str, list[dict[str, str]]]] = {}
    disagreements: list[str] = []
    for match in OCR_RESOURCE_RE.finditer(text):
        resource_id = match.group(0)
        prefix = next((entry for entry in OCR_RESOURCE_TYPES if resource_id.casefold().startswith(entry[0])), None)
        if not prefix:
            continue
        system, category = prefix[1], prefix[2]
        line_no = next((i for i, line in enumerate(lines) if resource_id.casefold() in line.casefold()), 0)
        local = "\n".join(lines[max(0, line_no - 2):min(len(lines), line_no + 3)])
        ownership_context = lines[line_no] if len(all_resource_ids) > 1 else text
        catalog = owners.get((system, resource_id), [])
        # Catalog links are authoritative even when the screenshot shows another name.
        linked_users = {o["user_id"] for o in catalog if o["user_id"]}
        if not catalog:
            for token, uid in identity_tokens.items():
                if re.search(r"(?<![\w@.+-])" + re.escape(token) + r"(?![\w@.+-])", ownership_context, re.I):
                    linked_users.add(uid)
        if not catalog and not linked_users:
            continue
        owners_payload = catalog or [{"user_id": uid, "email": "", "details": "OCR identity text"} for uid in sorted(linked_users)]
        # Compare the screenshot's visible full-name/email text with the catalog owner,
        # but never let a conflicting label replace catalog ownership.
        if catalog:
            owner_uids = {o["user_id"] for o in catalog if o["user_id"]}
            for token, uid in identity_tokens.items():
                if uid not in owner_uids and len(token) > 5 and re.search(r"(?<![\w@.+-])" + re.escape(token) + r"(?![\w@.+-])", lines[line_no], re.I):
                    disagreements.append(resource_id)
                    break
            owner_names = [identity_names[uid] for uid in owner_uids if uid in identity_names]
            if len(all_resource_ids) == 1 and not any(name.casefold() in text.casefold() for name in owner_names):
                nearby = "\n".join(lines[max(0, line_no - 2):line_no + 1])
                ui_labels = {"northstar shop", "audience operations", "customer operations", "production help",
                             "profile attributes", "customer search", "account platform", "live profile"}
                name_candidates = re.findall(r"\b([A-Z][a-z]+(?:[-'][A-Za-z]+)?)\s+([A-Z][a-z]+(?:[-'][A-Za-z]+)?)\b", nearby)
                if any((first + " " + last).casefold() not in ui_labels and
                       all((first + " " + last).casefold() != name.casefold() for name in owner_names)
                       for first, last in name_candidates):
                    disagreements.append(resource_id)
        state, normalized = ocr_state(resource_id, local)
        rows[resource_id] = (system, category, state, normalized, owners_payload)

    for resource_id, (system, category, state, normalized, owners_payload) in sorted(rows.items()):
        hit = text.casefold().find(resource_id.casefold())
        local = text[max(0, hit - 280):min(len(text), hit + len(resource_id) + 500)]
        payload = {"ocr_evidence": True, "ocr_text": text, "resource_context": local,
                   "owners": owners_payload, "resource_id": resource_id,
                   "category": category, "state": state}
        add_observation(db, evidence_id, file_time, system, resource_id, category,
                        state, normalized, record_payload(payload))
    return len(rows), sorted(set(disagreements))


def parse_sql(db: sqlite3.Connection, evidence_id: str, path: Path, file_time: str) -> int:
    # Execute each SQL snapshot in an isolated SQLite database, then inspect its tables.
    count = 0
    source = sqlite3.connect(":memory:")
    try:
        sql_text = path.read_text(encoding="utf-8-sig", errors="replace")
        source.executescript(sql_text)
        tables = source.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        table_names = [table for (table,) in tables]
        row_counts = {
            table: source.execute(f"SELECT COUNT(*) FROM {quote_identifier(table)}").fetchone()[0]
            for table in table_names
        }
        captured_match = re.search(r"(?im)^\s*--\s*Captured at:\s*(\S+)", sql_text)
        if not captured_match:
            captured_match = re.search(r"(?im)^\s*--\s*snapshot_completed_at=(\S+)", sql_text)
        snapshot_time = captured_match.group(1) if captured_match else file_time
        for table in table_names:
            if table.lower() in {"snapshot_scope", "metadata", "snapshot_metadata"}:
                cols = [r[1].lower() for r in source.execute(f"PRAGMA table_info({quote_identifier(table)})")]
                if "captured_at" in cols:
                    time_value = source.execute(f"SELECT captured_at FROM {quote_identifier(table)} LIMIT 1").fetchone()
                    if time_value and time_value[0]:
                        snapshot_time = str(time_value[0])
                        break
        db.execute("""INSERT INTO sql_snapshots
                      (evidence_id, captured_at, tables, row_counts) VALUES (?, ?, ?, ?)""",
                   (evidence_id, snapshot_time, json.dumps(table_names, ensure_ascii=False),
                    json.dumps(row_counts, ensure_ascii=False, sort_keys=True)))
        for (table,) in tables:
            cursor = source.execute(f"SELECT * FROM {quote_identifier(table)}")
            columns = [item[0] for item in cursor.description or ()]
            for values in cursor:
                row = dict(zip(columns, values))
                resource = first_value(row, RESOURCE_KEYS)
                if resource is None:
                    continue
                system = first_value(row, SYSTEM_KEYS) or table_system(table)
                category = first_value(row, CATEGORY_KEYS) or table
                state = first_value(row, STATE_KEYS) or ""
                timestamp = first_value(row, TIME_KEYS) or file_time
                add_observation(db, evidence_id, normalize(timestamp), normalize(system),
                                normalize(resource), normalize(category), normalize(state), normalized_state(row),
                                record_payload(row))
                count += 1
    finally:
        source.close()
    return count


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def build_database(output: Path | None = None, print_counts: bool = True) -> Path:
    output = output or (ROOT / "code" / "observations.sqlite")
    output = output if output.is_absolute() else ROOT / output
    output.parent.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, dict[str, str]] = {}
    with MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            manifest[row["file_path"].replace("\\", "/")] = row

    files = sorted(path for path in EVIDENCE_ROOT.rglob("*") if path.is_file())
    format_counts: Counter[str] = Counter()
    record_counts: Counter[str] = Counter()
    catalog_owners = read_catalog_owners()
    identity_tokens = read_identity_tokens()
    identity_names = read_identity_names()
    tesseract = tesseract_executable()
    ocr_disagreements: set[str] = set()

    with sqlite3.connect(output) as db:
        db.execute("DROP TABLE IF EXISTS observations")
        db.execute("DROP TABLE IF EXISTS sql_snapshots")
        db.execute("DROP TABLE IF EXISTS image_ocr")
        db.execute("""CREATE TABLE observations (
            evidence_id TEXT NOT NULL,
            captured_at TEXT NOT NULL,
            system_id TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            category TEXT NOT NULL,
            state TEXT NOT NULL,
            normalized_state TEXT NOT NULL,
            identifiers TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE sql_snapshots (
            evidence_id TEXT PRIMARY KEY,
            captured_at TEXT NOT NULL,
            tables TEXT NOT NULL,
            row_counts TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE image_ocr (
            evidence_id TEXT PRIMARY KEY,
            captured_at TEXT NOT NULL,
            ocr_text TEXT NOT NULL
        )""")
        db.execute("CREATE INDEX idx_observations_resource ON observations(resource_id)")
        db.execute("CREATE INDEX idx_observations_evidence ON observations(evidence_id)")
        for path in files:
            ext = path.suffix.lower()
            format_counts[ext or "<no extension>"] += 1
            if ext not in SUPPORTED:
                continue
            rel = path.relative_to(ROOT / "dataset").as_posix()
            metadata = manifest.get(rel, {})
            evidence_id = metadata.get("file_id", "")
            captured_at = metadata.get("captured_at", "")
            try:
                if ext == ".json":
                    added = parse_json(db, evidence_id, path, captured_at)
                elif ext == ".log":
                    added = parse_log(db, evidence_id, path, captured_at)
                elif ext == ".txt":
                    added = parse_text(db, evidence_id, path, captured_at)
                elif ext == ".pdf":
                    added = parse_pdf(db, evidence_id, path, captured_at, metadata.get("origin", ""))
                elif ext == ".png":
                    added, conflicts = parse_png(db, evidence_id, path, captured_at,
                                                 catalog_owners, identity_tokens, identity_names, tesseract)
                    ocr_disagreements.update(f"{evidence_id}:{resource}" for resource in conflicts)
                else:
                    added = parse_sql(db, evidence_id, path, captured_at)
                record_counts[ext] += added
            except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as exc:
                raise RuntimeError(f"Could not parse {path.relative_to(ROOT)}: {exc}") from exc
        db.commit()

    if print_counts:
        print("Evidence file counts by format:")
        for ext, count in sorted(format_counts.items()):
            treatment = " (skipped)" if ext in SKIPPED else ""
            print(f"  {ext}: {count}{treatment}")
        if ".png" in format_counts and not tesseract:
            print("PNG OCR skipped; Tesseract unavailable (set TESSERACT_CMD or install it on PATH)")
        print("Observation counts by parsed format:")
        for ext in sorted(SUPPORTED):
            print(f"  {ext}: {record_counts[ext]}")
        print(f"  total: {sum(record_counts.values())}")
        print("Observation counts by normalized state:")
        with sqlite3.connect(output) as db:
            for state, count in db.execute(
                "SELECT normalized_state, COUNT(*) FROM observations GROUP BY normalized_state ORDER BY normalized_state"
            ):
                print(f"  {state or '<empty>'}: {count}")
            observed = {row[0] for row in db.execute("SELECT DISTINCT evidence_id FROM observations")}
        all_ids = {row["file_id"] for row in manifest.values()}
        zero_ids = sorted(all_ids - observed)
        parsed_ids = {
            row["file_id"] for row in manifest.values()
            if Path(row["file_path"]).suffix.lower() in SUPPORTED
        }
        print(f"Evidence IDs with zero observations (all manifest formats): {len(zero_ids)}")
        print(f"Evidence IDs with zero observations (parsed formats only): {len(parsed_ids - observed)}")
        print(f"Database: {output}")
        print("OCR/catalog identity label conflicts (catalog ownership retained): " +
              (", ".join(sorted(ocr_disagreements)) if ocr_disagreements else "none"))
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "code" / "observations.sqlite",
                        help="SQLite database to create (default: code/observations.sqlite)")
    args = parser.parse_args()
    build_database(args.output)


if __name__ == "__main__":
    main()
