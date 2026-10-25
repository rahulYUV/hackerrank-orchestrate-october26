#!/usr/bin/env python3
"""Deterministic deletion-audit solver v0.

Run from any directory with:
    py code/main.py

Predictions use only request, identity, activity, policy, and parsed evidence inputs.
The public sample output is deliberately not read here.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import unicodedata
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from parse_evidence import build_database


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
OBS_DB = ROOT / "code" / "observations.sqlite"
OUTPUT = ROOT / "output.csv"
UNCERTAIN_OUTPUT = ROOT / "code" / "uncertain_requests.csv"

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def clean(value: Any) -> str:
    text = str(value or "").strip()
    return "" if text.casefold() in {"null", "none", "n/a", "unknown"} else text


def parse_time(value: str) -> datetime | None:
    if not clean(value):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def folded_text(value: str) -> str:
    return unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii").casefold()


DELETION_PATTERNS = (
    r"\bdelet(?:e|ed|ing|ion|ions)\b", r"\beras(?:e|ed|ing|ure)\b", r"\bremov(?:e|ed|al|ing)\b",
    r"\bforget\b", r"\bclose\b.{0,45}\b(account|profile)\b", r"\b(account|profile)\b.{0,45}\bclosed\b",
    r"\bsuppress(?:ion|ion definitive)?\b", r"\bsupprimer\b", r"\beffacer\b", r"\belimin\w*\b", r"\bborr\w*\b",
    r"\bexclu\w*\b", r"\bapag\w*\b", r"\bcancell\w*\b", r"\b(?:loesch|losch)\w*\b", r"\bentfern\w*\b",
    r"\bradera\b", r"\bverwijder\w*\b", r"\bschrap\w*\b", r"\bdestru\w*\b", r"\bannull\w*\b", r"\bstornier\w*\b",
    r"\u524a\u9664|\u6d88\u53bb|\u5220\u9664|\u522a\u9664|\u6e05\u9664|\u6ce8\u9500|\u92b7\u6236|\u6d88\u3059|\u6d88\u3057|\u629b\u6d88|\u89e3\u7d04|\u9000\u4f1a|\u30c7\u30fc\u30bf\u3092\u6d88",
    r"\uc0ad\uc81c|\uc81c\uac70|\uc9c0\uc6b0|\ud0c8\ud1f4",
    r"\u0939\u091f\u093e\u0928\u093e|\u0939\u091f\u093e\u090f\u0902|\u092e\u093f\u091f\u093e\u0928\u093e|\u0921\u093f\u0932\u0940\u091f|\u0928\u0937\u094d\u091f",
    r"\u062d\u0630\u0641|\u0625\u0632\u0627\u0644\u0629|\u0627\u0645\u0633\u062d|\u0625\u0644\u063a\u0627\u0621",
    r"削除|消去|删除|刪除|データを消",
)
NONDELETION_PATTERNS = (
    r"\bnot\s+(?:asking for|a request to)\s+(?:delet\w*|eras\w*|remov\w*)\b",
    r"\b(?:information|data|subject access)\s+request\b",
    r"\b(?:login|password|sign.?in)\b.{0,45}\b(?:reset|recover|help|access)\b",
    r"\b(?:remove|stop|unsubscribe|opt\s*out)\b.{0,60}\b(?:marketing|promotional|newsletter|email list)\w*\b",
    r"\b(?:marketing|promotional)\s+(?:emails?|messages?|lists?)\b",
    r"\bcopy\b", r"\binvoices?\b", r"\bdownload\w*\b", r"\breplace\w*\b",
    r"\b(?:keep|leave|retain|maintain)\b.{0,55}\b(account|profile|records?|history)\b",
    r"\b(?:account|profile)\b.{0,45}\b(?:active|as is|unchanged|in place)\b",
    r"\bdescarg\w*\b", r"\bcopi\w*\b", r"\breemplaz\w*\b", r"\bcambi\w*\b",
    r"\bfactur\w*\b", r"\bsubstitu\w*\b", r"\bbaixar\w*\b", r"\bt[eé]l[eé]charger\w*\b",
    r"\bremplacer\w*\b", r"\bfacture\w*\b", r"\b(?:behalten|lassen)\b",
    r"\bherunterladen\w*\b", r"\bkorrigier\w*\b", r"\brechnung\w*\b",
    r"\bscaric\w*\b", r"\bcopia\b", r"\bsostitu\w*\b", r"\bcorregg\w*\b", r"\bfattur\w*\b",
    r"\bactualiser\b", r"\btelecharger\w*\b", r"\bgarder\w*\b", r"\blaisser\w*\b",
    r"\u30a2\u30af\u30bb\u30b9|\u8a02\u6b63|\u5909\u66f4|\u30c0\u30a6\u30f3\u30ed\u30fc\u30c9|\u30b3\u30d4\u30fc|\u7f6e\u304d\u63db\u3048|\u7dad\u6301|\u8acb\u6c42\u66f8|\u524a\u9664\u3057\u306a\u3044",
    r"\uacc4\uc815\uc744?\s*(?:\uc720\uc9c0|\ub0a8\uaca8|\uacc4\uc18d)|\ub2e4\uc6b4\ub85c\ub4dc|\ubcf5\uc0ac|\uad50\uccb4|\ubcc0\uacbd|\uc218\uc815|\uccad\uad6c\uc11c|\uc0ad\uc81c\ud558\uc9c0\s*\ub9c8",
    r"\u0938\u0902\u0936\u094b\u0927\u093f\u0924|\u092c\u0926\u0932\u0947|\u0921\u093e\u0909\u0928\u0932\u094b\u0921|\u092a\u094d\u0930\u0924\u093f|\u0930\u0916\u0947\u0902|\u092c\u093f\u0932",
    r"\u062a\u063a\u064a\u064a\u0631|\u062a\u0635\u062d\u064a\u062d|\u062a\u0646\u0632\u064a\u0644|\u0646\u0633\u062e\u0629|\u0641\u0627\u062a\u0648\u0631\u0629|\u0627\u062d\u062a\u0641\u0638|\u0644\u0627\s*\u062a\u062d\u0630\u0641",
    r"\u4fdd\u7559\u8d26\u6237|\u4e0b\u8f7d|\u590d\u5236|\u66f4\u6362|\u4fee\u6539|\u53d1\u7968|\u4e0d\u8981\u5220\u9664",
    r"\baccess\b", r"\bcopy\b.{0,30}\b(data|information|record)\b", r"\bexport\b", r"\bportability\b",
    r"\bcorrect\w*\b", r"\brectif\w*\b", r"\bupdate\b", r"\bchange\b", r"\bmodify\b",
    r"\bunsubscribe\b", r"\bopt\s*out\b", r"\bmarketing\b", r"\bstop\b.{0,30}\b(email|marketing|newsletter)\b",
    r"\bshow me\b.{0,30}\b(data|information)\b", r"\bsend me\b.{0,30}\b(copy|export)\b",
    r"\bactualizar\b", r"\bcorregir\b", r"\bacceso\b", r"\bexportar\b", r"\brectifier\b", r"\bmodifier\b",
    r"\bzugriff\b", r"\baendern\b", r"\bactualiser\b", r"\bアクセス\b|\b訂正\b|\b変更\b",
)
NEGATED_DELETION_PATTERNS = (
    r"\b(?:do not|don't|dont) close (?:the )?(?:account|profile)\b",
    r"\bnot\s+(?:asking for|a request to)\s+(?:delet\w*|eras\w*|remov\w*)\b",
    r"\b(?:not asking|not a request)\b.{0,50}\b(?:delet\w*|eras\w*|remov\w*)\b",
    r"\b(?:no|nao)\s+(?:quero|quiero|queremos)\s+(?:delet\w*|exclu\w*|apagar|borrar|eliminar)\b",
    r"\b(?:nicht|kein)\w*\b.{0,30}\b(?:loeschen|loschen|entfernen)\b",
    r"\bnon\b.{0,25}\b(?:voglio|cancellare|eliminare|rimuovere)\b",
    r"\bne\b.{0,25}\bpas\b.{0,20}\b(?:supprimer|effacer)\b",
    r"\u524a\u9664.{0,12}\u3057\u307e\u305b\u3093|\u524a\u9664.{0,12}\u5e0c\u671b\u3057\u307e\u305b\u3093",
    r"\uc0ad\uc81c.{0,12}\uc694\uccad\ud558\uc9c0\s*\uc54a|\uc0ad\uc81c\ud558\uc9c0\s*\uc54a",
    r"\u0928\u0939\u0940\u0902.{0,20}(?:\u0939\u091f\u093e\u090f|\u092e\u093f\u091f\u093e\u090f)",
    r"\u0644\u0627.{0,20}(?:\u0623\u0631\u064a\u062f|\u0627\u0631\u064a\u062f).{0,20}(?:\u062d\u0630\u0641|\u0625\u0632\u0627\u0644\u0629)",
    r"\b(?:no|nao)\s+(?:delete|deletar|apagar|excluir|eliminar|borrar)\b",
    r"\bnon\s+(?:cancellare|eliminare|rimuovere)\b", r"\b(?:nicht|kein)\w*\s+(?:loeschen|loschen|entfernen)\b",
    r"\bne\s+pas\s+(?:supprimer|effacer)\b",
    r"\u524a\u9664\u3057\u306a\u3044|\uc0ad\uc81c\ud558\uc9c0\s*\ub9c8|\u4e0d\u8981\u5220\u9664|\u5225\u522a\u9664",
    r"\u0928\u0939\u0940\u0902\s*(?:\u0939\u091f\u093e\u0913|\u092e\u093f\u091f\u093e\u0913)|\u0644\u0627\s*\u062a\u062d\u0630\u0641",
    r"\bdo not (?:delete|erase|remove)\b", r"\bdon't (?:delete|erase|remove)\b",
    r"\bnot (?:a )?(?:deletion|erasure) request\b", r"\bwithout (?:deleting|erasing|removing)\b",
    r"\bno (?:deletion|erasure)\b", r"\bno me (?:elimines|borres)\b",
)
NONDELETION_SCOPE_PATTERNS = (
    r"\b(?:remove|stop|unsubscribe|opt\s*out)\b.{0,70}\b(?:marketing|promotional|newsletter|email lists?)\b.{0,35}\bonly\b",
)


def classify_request(text: str) -> tuple[str, str]:
    normalized = folded_text(text)
    def matches(patterns: tuple[str, ...]) -> bool:
        return any(re.search(pattern, normalized, flags=re.IGNORECASE) or
                   re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)
    negated = matches(NEGATED_DELETION_PATTERNS)
    nondeletion = matches(NONDELETION_PATTERNS)
    nondeletion_scope = matches(NONDELETION_SCOPE_PATTERNS)
    deletion = matches(DELETION_PATTERNS)
    # Preserve scripts that ASCII folding removes, and treat a request to audit whether
    # a previous deletion succeeded as an authorized deletion-audit request.
    raw_deletion = bool(re.search(r"削除|消去|删除|刪除|データを消|完全な削除", text))
    audit_of_deletion = bool(re.search(
        r"\b(?:verify|confirm|check|audit|investigate)\b.{0,100}\b(?:deleted|removed|erased|gone)\b|"
        r"\b(?:deleted|removed|erased)\b.{0,80}\b(?:verify|confirm|check|audit)\b",
        normalized,
    ))
    deletion = deletion or raw_deletion or audit_of_deletion
    if negated:
        return "NOT_APPLICABLE", "explicitly negated deletion"
    if nondeletion_scope:
        return "NOT_APPLICABLE", "marketing or promotional opt-out limited to those messages"
    if deletion:
        return "DELETE", "deletion/erasure language or a deletion-success audit request found"
    if nondeletion:
        return "NOT_APPLICABLE", "access, correction, export, marketing, or other non-deletion language found"
    return "DELETE", "default deletion decision; no non-deletion cue found"


def resolve_identity(request: dict[str, str], identities: list[dict[str, str]],
                     audits: list[dict[str, str]]) -> tuple[str, set[str]]:
    requested_email = clean(request.get("email")).casefold()
    user_ids: set[str] = set()
    for row in identities:
        if clean(row.get("email")).casefold() == requested_email:
            user_ids.add(clean(row.get("user_id")))
    for row in audits:
        if clean(row.get("field_name")).casefold() == "email":
            if requested_email in {clean(row.get("old_value")).casefold(), clean(row.get("new_value")).casefold()}:
                user_ids.add(clean(row.get("user_id")))
    user_ids.discard("")

    values = {x.casefold() for x in user_ids if x}
    for row in identities:
        if clean(row.get("user_id")) in user_ids:
            for field in ("email", "phone", "email_hash"):
                value = clean(row.get(field)).casefold()
                if value:
                    values.add(value)
    for row in audits:
        if clean(row.get("user_id")) in user_ids and clean(row.get("field_name")).casefold() in {"email", "phone", "email_hash", "email_sha256"}:
            for field in ("old_value", "new_value"):
                value = clean(row.get(field)).casefold()
                if value:
                    values.add(value)
    return ";".join(sorted(user_ids)), values


def payload_has_identity(payload_text: str, values: set[str]) -> bool:
    folded = payload_text.casefold()
    for value in values:
        value = clean(value).casefold()
        if value and re.search(r"(?<![a-z0-9])" + re.escape(value) + r"(?![a-z0-9])", folded):
            return True
    return False


def nested_payloads(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            if isinstance(child, (dict, list)):
                yield from nested_payloads(child)
            elif isinstance(child, str) and child[:1] in "{[":
                try:
                    yield from nested_payloads(json.loads(child))
                except (json.JSONDecodeError, TypeError):
                    pass
    elif isinstance(value, list):
        for child in value:
            yield from nested_payloads(child)


def user_reference_match(payload: Any, user_ids: set[str]) -> bool:
    # Trace joins can carry the stable subject key on the start/query event and
    # the resource on the completion event. Accept those only when the joined
    # value exactly equals a known user_id; arbitrary trace IDs remain inert.
    keys = {"user_id", "subject_reference", "subject_ref", "customer_reference",
            "customer_ref", "correlation_key", "subject_key"}
    wanted = {clean(u).casefold() for u in user_ids if clean(u)}
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            return False

    def scalar_values(value: Any):
        if isinstance(value, list):
            for child in value:
                yield from scalar_values(child)
        elif isinstance(value, dict):
            for child in value.values():
                yield from scalar_values(child)
        elif value is not None:
            yield str(value)

    for obj in nested_payloads(payload):
        for key, value in obj.items():
            if str(key).casefold() in keys:
                if any(clean(candidate).casefold() in wanted for candidate in scalar_values(value)):
                    return True
    return False


def observation_owner_match(payload: Any, identity_values: set[str], user_ids: set[str]) -> bool:
    """Use catalog/locally linked OCR owners, never arbitrary screenshot list labels."""
    parsed = payload
    if isinstance(parsed, str):
        try:
            parsed = json.loads(parsed)
        except (json.JSONDecodeError, TypeError):
            return False
    if isinstance(parsed, dict) and parsed.get("ocr_evidence") is True:
        wanted_ids = {clean(value).casefold() for value in user_ids if clean(value)}
        wanted_values = {clean(value).casefold() for value in identity_values if clean(value)}
        for owner in parsed.get("owners", []):
            if not isinstance(owner, dict):
                continue
            if clean(owner.get("user_id")).casefold() in wanted_ids:
                return True
            if clean(owner.get("email")).casefold() in wanted_values:
                return True
        return False
    return matching_identity_in_payload(payload, identity_values) or user_reference_match(payload, user_ids)


def audit_owner_match(payload: Any, user_ids: set[str]) -> bool:
    """Match an audit row's stable owner link, irrespective of capture time."""
    owner_keys = {"subject_ref", "subject_reference", "correlation_key"}
    wanted = {clean(uid).casefold() for uid in user_ids if clean(uid)}
    if not wanted:
        return False
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            return False
    for obj in nested_payloads(payload):
        for key, value in obj.items():
            if str(key).casefold() not in owner_keys:
                continue
            values = value if isinstance(value, list) else [value]
            if any(clean(v).casefold() in wanted for v in values if v is not None):
                return True
    return False


def table_system(table: str) -> str:
    name = table.casefold()
    maps = (
        (("analytics", "telemetry"), "analytics_platform"),
        (("search", "index"), "search_service"),
        (("support", "ticket", "message", "attachment"), "support_platform"),
        (("export",), "export_service"),
        (("backup", "archive"), "backup_service"),
        (("connector", "flow", "integration"), "integration_service"),
        (("audit", "security"), "security_service"),
        (("identity", "tombstone"), "identity_service"),
        (("account", "profile"), "account_service"),
        (("legal", "retention", "order"), "legal_service"),
    )
    for fragments, system in maps:
        if any(fragment in name for fragment in fragments):
            return system
    return ""


def category_for(system: str, resource: str, observed_category: str) -> str:
    cat = clean(observed_category).upper()
    rule_categories = {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
                       "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE", "PRODUCT_TELEMETRY",
                       "USER_EXPORT", "MARKETING_PROFILE", "EMAIL_DELIVERY_LOG", "SECURITY_AUDIT_LOG",
                       "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE", "ACCOUNT_TOMBSTONE"}
    if cat in rule_categories:
        return cat

    rid = resource.casefold()
    sys = system.casefold()
    if rid.startswith("tombstone_") or sys == "identity_service":
        return "ACCOUNT_TOMBSTONE"
    if rid.startswith("audit_record_") or sys == "security_service":
        return "SECURITY_AUDIT_LOG"
    if rid.startswith("data_flow_") or "flow" in cat or (sys == "integration_service" and rid.startswith("connector_")):
        return "DATA_FLOW"
    if rid.startswith("backup_") or sys == "backup_service":
        return "BACKUP_ARCHIVE"
    if rid.startswith("account_") or sys == "account_service":
        return "USER_PROFILE"
    if rid.startswith("search_") or sys == "search_service":
        return "SEARCH_INDEX_ENTRY"
    if rid.startswith("analytics_") or sys == "analytics_platform":
        return "PRODUCT_TELEMETRY" if "telemetry" in cat else "ANALYTICS_PROFILE"
    if rid.startswith("export_") or sys == "export_service":
        return "USER_EXPORT"
    if rid.startswith("marketing_") or "marketing" in sys:
        return "MARKETING_PROFILE"
    if rid.startswith("object_") or sys == "object_storage":
        return "SUPPORT_ATTACHMENT"
    if rid.startswith("support_") or sys == "support_platform":
        if "attach" in cat or "attachment" in rid or "ticket_attachment" in cat:
            return "SUPPORT_ATTACHMENT"
        return "SUPPORT_MESSAGE"
    if "email_delivery" in rid or "email_delivery" in cat:
        return "EMAIL_DELIVERY_LOG"
    if "cache" in rid or "cache" in cat:
        return "CACHE_ENTRY"
    if "legal" in sys or "retention" in cat:
        return "LEGAL_HOLD_RECORD"
    return cat


def parse_bool(value: Any) -> bool | None:
    text = clean(value).casefold()
    if text in {"1", "true", "yes", "on", "enabled", "active", "allowed"}:
        return True
    if text in {"0", "false", "no", "off", "disabled", "inactive", "blocked", "denied"}:
        return False
    return None


def has_direct_pii(payload: Any) -> bool:
    fields = {"name", "full_name", "display_name", "email", "phone", "email_hash", "email_sha256",
              "requester_name", "requester_email", "requester_phone", "customer_name", "customer_email",
              "customer_phone", "matched_value", "lookup_key"}
    for obj in nested_payloads(payload):
        for key, value in obj.items():
            if str(key).casefold() in fields and clean(value):
                return True
    return False


def matching_identity_in_payload(payload: Any, identity_values: set[str]) -> bool:
    parsed = payload
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            pass
    text_parts: list[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                text_parts.append(str(key))
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)
        elif isinstance(value, str):
            text_parts.append(value)
        elif value is not None:
            text_parts.append(str(value))

    collect(parsed)
    # Search decoded scalar text as well as its serialized form. This preserves
    # literal boundaries around emails/phones that JSON escapes as backslash-n.
    searchable = "\n".join(text_parts) + "\n" + json.dumps(payload, ensure_ascii=False, default=str)
    return payload_has_identity(searchable, identity_values)


def evidence_capture(evidence_id: str, manifest: dict[str, dict[str, str]]) -> datetime | None:
    row = manifest.get(evidence_id)
    return parse_time(row.get("captured_at", "")) if row else None


def output_step(phase: str, system: str, resource: str, operation: str,
                state: str, evidence_id: str) -> dict[str, Any]:
    return {"step_no": 0, "phase": phase, "system_id": system, "resource_id": resource,
            "operation": operation, "state": state, "evidence_id": evidence_id}


def load_context(rebuild_observations: bool = True, print_counts: bool = False,
                 requests_path: Path | None = None) -> dict[str, Any]:
    if rebuild_observations or not OBS_DB.exists():
        build_database(OBS_DB, print_counts=print_counts)
    identities = read_csv(DATA / "user_identities.csv")
    audits = read_csv(DATA / "user_audit_log.csv")
    activities = read_csv(DATA / "system_activity.csv")
    requests = read_csv(requests_path or (DATA / "deletion_requests.csv"))
    rules = {clean(r["data_category"]).upper(): r for r in read_csv(DATA / "deletion_rules.csv")}
    manifest = {r["file_id"]: r for r in read_csv(DATA / "evidence_files.csv")}

    import sqlite3
    with sqlite3.connect(OBS_DB) as db:
        db.row_factory = sqlite3.Row
        observations = [dict(row) for row in db.execute(
            "SELECT evidence_id,captured_at,system_id,resource_id,category,state,normalized_state,identifiers FROM observations"
        )]
        snapshots = {}
        for row in db.execute("SELECT evidence_id,captured_at,tables,row_counts FROM sql_snapshots"):
            snapshots[row[0]] = {"captured_at": row[1], "tables": json.loads(row[2]), "row_counts": json.loads(row[3])}
    return {"identities": identities, "audits": audits, "activities": activities,
            "requests": requests, "rules": rules, "manifest": manifest,
            "observations": observations, "snapshots": snapshots}


def select_latest_observation(rows: list[dict[str, Any]], audit_at: datetime,
                              manifest: dict[str, dict[str, str]]) -> dict[str, Any] | None:
    eligible = []
    for row in rows:
        capture = evidence_capture(row["evidence_id"], manifest)
        try:
            payload = json.loads(row.get("identifiers", "{}"))
        except (json.JSONDecodeError, TypeError):
            payload = {}
        event = clean(payload.get("event", "")).casefold() if isinstance(payload, dict) else ""
        # A *_started event only records an attempted lookup, not the lookup result.
        if event.endswith("_started"):
            continue
        if capture and capture <= audit_at:
            eligible.append((capture, row["evidence_id"], row))
    return max(eligible, key=lambda x: (x[0], x[1]))[2] if eligible else None


def identity_candidate_pairs(identity_values: set[str], user_ids: set[str],
                             observations: list[dict[str, Any]], audit_at: datetime,
                             manifest: dict[str, dict[str, str]]) -> tuple[set[tuple[str, str]], dict[tuple[str, str], list[dict[str, Any]]]]:
    def infer_system(resource_id: str) -> str:
        prefixes = (
            ("account_", "account_service"), ("search_", "search_service"),
            ("support_", "support_platform"), ("analytics_", "analytics_platform"),
            ("export_", "export_service"), ("backup_", "backup_service"),
            ("data_flow_", "integration_service"), ("connector_", "integration_service"),
            ("audit_record_", "security_service"), ("tombstone_", "identity_service"),
            ("legal_hold_", "legal_service"), ("marketing_", "marketing_platform"),
            ("object_", "object_storage"),
        )
        folded = resource_id.casefold()
        return next((system for prefix, system in prefixes if folded.startswith(prefix)), "")

    found: set[tuple[str, str]] = set()
    rows_by_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in observations:
        system, resource = clean(row["system_id"]), clean(row["resource_id"])
        if not system:
            system = infer_system(resource)
            if system:
                row = {**row, "system_id": system}
        if not system or not resource:
            continue
        capture = evidence_capture(row["evidence_id"], manifest)
        if not capture:
            continue
        pair = (system, resource)
        # Later captures may establish ownership of a stable resource ID. They
        # never enter rows_by_pair, which is the source of state/citation and
        # remains strictly limited to captures at or before audit_at.
        if observation_owner_match(row["identifiers"], identity_values, user_ids):
            found.add(pair)
        if capture <= audit_at:
            rows_by_pair[pair].append(row)
    return found, rows_by_pair


def get_activity_candidates(request: dict[str, str], activities: list[dict[str, str]],
                            audit_at: datetime, identity_values: set[str], user_ids: set[str],
                            rows_by_pair: dict[tuple[str, str], list[dict[str, Any]]],
                            mode: str) -> set[tuple[str, str]]:
    reported = parse_time(request.get("reported_at", ""))
    if not reported:
        return set()
    delta = timedelta(hours=6)
    raw: set[tuple[str, str]] = set()
    confirmed: set[tuple[str, str]] = set()
    nearby_primary_accounts: set[tuple[str, str]] = set()
    user_id_set = {x.casefold() for x in user_ids if x}
    for row in activities:
        event_at = parse_time(row.get("event_time", ""))
        event_type = clean(row.get("event_type")).upper()
        if (event_type == "LINK_RESOURCE_IDENTITY" and event_at and event_at <= audit_at and
                clean(row.get("source_system")).casefold() == "data_catalog"):
            pair = (clean(row.get("target_system")), clean(row.get("resource_id")))
            details = clean(row.get("details"))
            if (all(pair) and (payload_has_identity(details, identity_values) or
                               any(re.search(r"(?<![a-z0-9])" + re.escape(uid) + r"(?![a-z0-9])",
                                             details.casefold()) for uid in user_id_set))):
                confirmed.add(pair)
        if clean(row.get("source_system")).casefold() != "deletion_worker":
            continue
        if not event_at or event_at > audit_at or abs(event_at - reported) > delta:
            continue
        pair = (clean(row.get("target_system")), clean(row.get("resource_id")))
        if not all(pair):
            continue
        raw.add(pair)
        if (clean(row.get("event_type")).upper() == "DELETE_RECORD" and
                pair[0].casefold() == "account_service" and
                pair[1].casefold().startswith("account_")):
            nearby_primary_accounts.add(pair)
        details = clean(row.get("details")).casefold()
        linked = payload_has_identity(details, identity_values)
        if not linked:
            linked = any(token and token in details for token in user_id_set)
        if not linked:
            linked = any(observation_owner_match(obs["identifiers"], identity_values, user_ids)
                         for obs in rows_by_pair.get(pair, []))
        if linked:
            confirmed.add(pair)
    # A single primary-account DELETE_RECORD in the request's narrow worker
    # window can link the account resource even when the worker log omits PII.
    # Ambiguous windows remain unconfirmed to avoid promoting decoy resources.
    if len(nearby_primary_accounts) == 1 and user_ids:
        confirmed.update(nearby_primary_accounts)
    return raw if mode == "raw" else confirmed


def sql_scope_state(pair: tuple[str, str], audit_at: datetime, context: dict[str, Any]) -> tuple[str, str, str] | None:
    system, _resource = pair
    options = []
    for evidence_id, snap in context["snapshots"].items():
        capture = parse_time(snap["captured_at"])
        file_capture = evidence_capture(evidence_id, context["manifest"])
        if not capture or not file_capture or capture > audit_at or file_capture > audit_at:
            continue
        applicable = [t for t in snap["tables"] if table_system(t) == system]
        # Require actual rows in a mapped system table. Schema-only inventories do
        # not prove an empty production resource, while non-empty snapshots can.
        applicable = [t for t in applicable if int(snap["row_counts"].get(t, 0)) > 0]
        if applicable:
            options.append((max(capture, file_capture), evidence_id, sorted(applicable)[0]))
    return ("ABSENT", max(options)[1], max(options)[2]) if options else None


def json_scope_state(pair: tuple[str, str], audit_at: datetime,
                     observations: list[dict[str, Any]], manifest: dict[str, dict[str, str]]) -> tuple[str, str, str] | None:
    system, resource = pair
    choices = []
    for row in observations:
        if clean(row.get("resource_id")) or row.get("normalized_state") != "ABSENT" or clean(row.get("system_id")) != system:
            continue
        if table_system(clean(row.get("category", ""))) != system:
            continue
        capture = evidence_capture(row["evidence_id"], manifest)
        row_time = parse_time(row.get("captured_at", ""))
        if capture and capture <= audit_at and (not row_time or row_time <= audit_at):
            choices.append((capture, row["evidence_id"], clean(row.get("category"))))
    if not choices:
        return None
    latest = max(choices)
    return ("ABSENT", latest[1], latest[2])


def positive_direct_observation(row: dict[str, Any]) -> bool:
    """Whether a resource-specific row directly establishes resource presence."""
    state = clean(row.get("normalized_state")).upper()
    if not clean(row.get("resource_id")) or state == "ABSENT":
        return False
    try:
        payload = json.loads(row.get("identifiers", "{}"))
    except (TypeError, json.JSONDecodeError):
        payload = {}
    objects = list(nested_payloads(payload))
    status_codes = [value for obj in objects for key, value in obj.items()
                    if str(key).casefold() == "status_code"]
    row_counts = [value for obj in objects for key, value in obj.items()
                  if str(key).casefold() == "rows"]
    if any(str(value).strip() == "200" for value in status_codes):
        return True
    if any(str(value).strip().isdigit() and int(str(value).strip()) > 0 for value in row_counts):
        return True
    if status_codes or row_counts:
        return False
    return state in {"PRESENT", "IDENTIFIABLE", "REDACTED", "ANONYMIZED",
                     "ACTIVE", "BLOCKED", "DISABLED"}


def current_resource(pair: tuple[str, str], rows_by_pair: dict[tuple[str, str], list[dict[str, Any]]],
                     audit_at: datetime, context: dict[str, Any]) -> dict[str, Any] | None:
    row = select_latest_observation(rows_by_pair.get(pair, []), audit_at, context["manifest"])
    scopes = [x for x in [sql_scope_state(pair, audit_at, context),
                           json_scope_state(pair, audit_at, context["observations"], context["manifest"])] if x]
    if scopes:
        scope_evidence = max(scopes, key=lambda x: evidence_capture(x[1], context["manifest"]) or datetime.min.replace(tzinfo=timezone.utc))
        row_capture = evidence_capture(row["evidence_id"], context["manifest"]) if row else None
        scope_capture = evidence_capture(scope_evidence[1], context["manifest"])
        # A later empty scope does not override an earlier direct positive
        # resource observation. Empty scopes describe their collection; they
        # do not establish that the resource was absent from every system table.
        if (row and row_capture and scope_capture and scope_capture > row_capture and
                positive_direct_observation(row)):
            return {**row, "scope": False}
        if not row or (scope_capture and row_capture and scope_capture > row_capture):
            return {"system_id": pair[0], "resource_id": pair[1], "category": scope_evidence[2],
                    "normalized_state": "ABSENT", "state": "ABSENT", "evidence_id": scope_evidence[1],
                    "identifiers": "{}", "scope": True}
    if not row:
        return None
    return {**row, "scope": False}


def get_retention_action(category: str, resource: dict[str, Any], audit_at: datetime,
                         rules: dict[str, dict[str, str]]) -> str:
    if category == "DATA_FLOW":
        return "DISABLE_DATA_FLOW"
    if category == "BACKUP_ARCHIVE":
        return "BLOCK_RESTORE"
    if category == "LEGAL_HOLD_RECORD":
        # Rule 13 is conditional on a supplied, active legal hold. A future
        # accounting/tax retention date by itself does not establish that condition.
        payload = resource.get("identifiers", "")
        try:
            parsed = json.loads(payload) if isinstance(payload, str) else payload
        except (json.JSONDecodeError, TypeError):
            parsed = {}
        for obj in nested_payloads(parsed):
            for key, value in obj.items():
                name = str(key).casefold()
                if name in {"legal_hold_active", "hold_active", "is_legal_hold"} and parse_bool(value) is True:
                    return "RETAIN"
                if name in {"legal_hold_status", "hold_status"} and clean(value).casefold() in {"active", "open"}:
                    return "RETAIN"
        text = json.dumps(parsed, ensure_ascii=False, default=str).casefold()
        if re.search(r"legal[ _-]hold.{0,40}\b(active|open)\b", text):
            return "RETAIN"
        return ""
    rule = rules.get(category)
    if not rule:
        return ""
    action = clean(rule.get("required_action")).upper()
    if action == "DELETE":
        return "DELETE_RECORD"
    if action == "REDACT":
        return "REDACT_RECORD"
    if action == "ANONYMIZE":
        return "ANONYMIZE_RECORD"
    if action == "RETAIN":
        return "RETAIN"
    return ""


def observed_state(resource: dict[str, Any], category: str, identity_values: set[str]) -> str:
    state = clean(resource.get("normalized_state")).upper()
    payload = resource.get("identifiers", "")
    try:
        values = json.loads(payload) if isinstance(payload, str) else payload
    except (json.JSONDecodeError, TypeError):
        values = {}
    if category == "DATA_FLOW":
        enabled = None
        for obj in nested_payloads(values):
            if "enabled" in {str(k).casefold() for k in obj}:
                enabled = parse_bool(next(v for k, v in obj.items() if str(k).casefold() == "enabled"))
                break
        if enabled is not None:
            return "ACTIVE" if enabled else "DISABLED"
    if category == "BACKUP_ARCHIVE":
        for obj in nested_payloads(values):
            for key, value in obj.items():
                if str(key).casefold() == "restore_allowed":
                    allowed = parse_bool(value)
                    if allowed is not None:
                        return "ACTIVE" if allowed else "BLOCKED"
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"} and state == "ANONYMIZED":
        # A remaining stable user/customer reference still makes analytics attributable.
        linked_keys = {"user_id", "customer_reference", "subject_reference", "subject_ref"}
        for obj in nested_payloads(values):
            for key, value in obj.items():
                if str(key).casefold() in linked_keys and clean(value).casefold() in identity_values:
                    return "IDENTIFIABLE"
    return state or "PRESENT"


def verify_operation(action: str) -> tuple[str, str]:
    return {
        "DELETE_RECORD": ("VERIFY_RECORD_ABSENT", "ABSENT"),
        "REDACT_RECORD": ("VERIFY_RECORD_REDACTED", "REDACTED"),
        "ANONYMIZE_RECORD": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
        "RETAIN": ("VERIFY_RECORD_PRESENT", "PRESENT"),
        "DISABLE_DATA_FLOW": ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
        "BLOCK_RESTORE": ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
    }.get(action, ("", ""))


def evaluate_resource(pair: tuple[str, str], resource: dict[str, Any], user_ids: set[str],
                      identity_values: set[str], audit_at: datetime,
                      rules: dict[str, dict[str, str]]) -> dict[str, Any] | None:
    category = category_for(pair[0], pair[1], clean(resource.get("category")))
    action = get_retention_action(category, resource, audit_at, rules)
    if not action:
        return None
    state = observed_state(resource, category, identity_values)
    payload = resource.get("identifiers", "")
    try:
        parsed = json.loads(payload) if isinstance(payload, str) else payload
    except (json.JSONDecodeError, TypeError):
        parsed = {}
    identity_link = matching_identity_in_payload(parsed, identity_values)
    direct_pii = has_direct_pii(parsed)

    violation = False
    finding_operation = ""
    finding_state = ""
    remediation_state = ""
    if action == "DELETE_RECORD":
        violation = state != "ABSENT"
        finding_operation, finding_state, remediation_state = "REPORT_REMAINING_RECORD", "PRESENT", "ABSENT"
    elif action in {"REDACT_RECORD", "ANONYMIZE_RECORD"}:
        violation = state not in ({"REDACTED"} if action == "REDACT_RECORD" else {"ANONYMIZED"})
        if action == "REDACT_RECORD" and category != "ACCOUNT_TOMBSTONE":
            # Stable subject/customer references may be retained by redaction policy;
            # only direct identifying fields make a redacted record noncompliant.
            violation = violation and (state == "IDENTIFIABLE" or direct_pii)
        if action == "ANONYMIZE_RECORD":
            violation = state != "ANONYMIZED" or identity_link
        finding_operation, finding_state = "REPORT_EXPOSED_PII", "PRESENT"
        remediation_state = "REDACTED" if action == "REDACT_RECORD" else "ANONYMIZED"
    elif action == "DISABLE_DATA_FLOW":
        violation = state == "ACTIVE"
        finding_operation, finding_state, remediation_state = "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "DISABLED"
    elif action == "BLOCK_RESTORE":
        violation = state == "ACTIVE"
        finding_operation, finding_state, remediation_state = "REPORT_RESTORE_RISK", "ACTIVE", "BLOCKED"
    elif action == "RETAIN":
        if state == "ABSENT":
            return None
        return {"pair": pair, "category": category, "action": action, "state": state,
                "evidence_id": resource["evidence_id"], "violation": False}

    return {"pair": pair, "category": category, "action": action, "state": state,
            "evidence_id": resource["evidence_id"], "violation": violation,
            "finding_operation": finding_operation, "finding_state": finding_state,
            "remediation_state": remediation_state}


def solve_case(request: dict[str, str], context: dict[str, Any],
               activity_mode: str = "confirmed",
               include_late_audit_ownership: bool = True) -> tuple[dict[str, Any], bool, str]:
    intent, reason = classify_request(request.get("request_text", ""))
    if intent != "DELETE":
        return {"case_id": request["case_id"], "deletion_status": "NOT_APPLICABLE", "steps": []}, intent == "UNCERTAIN", reason

    user_ids_joined, identity_values = resolve_identity(request, context["identities"], context["audits"])
    user_ids = {x for x in user_ids_joined.split(";") if x}
    audit_at = parse_time(request.get("audit_at", ""))
    if not audit_at:
        return {"case_id": request["case_id"], "deletion_status": "INCOMPLETE", "steps": []}, True, "missing audit_at"
    a_pairs, rows_by_pair = identity_candidate_pairs(identity_values, user_ids,
                                                    context["observations"], audit_at,
                                                    context["manifest"])
    b_pairs = get_activity_candidates(request, context["activities"], audit_at,
                                      identity_values, user_ids, rows_by_pair, activity_mode)
    candidate_pairs = a_pairs | b_pairs

    assessments = []
    for pair in sorted(candidate_pairs):
        current = current_resource(pair, rows_by_pair, audit_at, context)
        if not current:
            continue
        assessment = evaluate_resource(pair, current, user_ids, identity_values,
                                       audit_at, context["rules"])
        if assessment:
            assessments.append(assessment)

    violations = [a for a in assessments if a["violation"]]
    status = "INCOMPLETE" if violations else "COMPLETE"
    if status == "INCOMPLETE" and include_late_audit_ownership:
        assessed_pairs = {a["pair"] for a in assessments}
        owner_pairs = set()
        for observation in context["observations"]:
            resource = clean(observation.get("resource_id"))
            if not resource.casefold().startswith("audit_record_"):
                continue
            if audit_owner_match(observation.get("identifiers", ""), user_ids):
                system = clean(observation.get("system_id")) or "security_service"
                owner_pairs.add((system, resource))
        for pair in sorted(owner_pairs - assessed_pairs):
            assessments.append({"pair": pair, "category": "SECURITY_AUDIT_LOG",
                                "action": "RETAIN", "state": "PRESENT",
                                "evidence_id": "", "violation": False})
    steps: list[dict[str, Any]] = []
    if status == "INCOMPLETE":
        for item in violations:
            steps.append(output_step("FINDING", item["pair"][0], item["pair"][1],
                                     item["finding_operation"], item["finding_state"], item["evidence_id"]))
        for item in violations:
            steps.append(output_step("REMEDIATION", item["pair"][0], item["pair"][1],
                                     item["action"], item["remediation_state"], ""))
        for item in assessments:
            operation, state = verify_operation(item["action"])
            if operation:
                steps.append(output_step("VERIFICATION", item["pair"][0], item["pair"][1],
                                         operation, state, ""))
    else:
        for item in assessments:
            operation, state = verify_operation(item["action"])
            if operation:
                steps.append(output_step("VERIFICATION", item["pair"][0], item["pair"][1],
                                         operation, state, item["evidence_id"]))

    steps.sort(key=lambda s: (PHASE_ORDER[s["phase"]], OPERATION_ORDER[s["operation"]],
                              s["system_id"], s["resource_id"]))
    for no, step in enumerate(steps, 1):
        step["step_no"] = no
    return {"case_id": request["case_id"], "deletion_status": status, "steps": steps}, False, reason


def predict_all(context: dict[str, Any], activity_mode: str = "confirmed",
                include_late_audit_ownership: bool = True) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    output, uncertain = [], []
    for request in sorted(context["requests"], key=lambda x: x["case_id"]):
        prediction, is_uncertain, reason = solve_case(request, context, activity_mode,
                                                      include_late_audit_ownership)
        output.append(prediction)
        if is_uncertain:
            uncertain.append({"case_id": request["case_id"], "email": request.get("email", ""),
                              "request_text": request.get("request_text", ""), "reason": reason})
    return output, uncertain


def write_output(rows: list[dict[str, Any]], path: Path = OUTPUT) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        for row in sorted(rows, key=lambda x: x["case_id"]):
            writer.writerow({"case_id": row["case_id"], "deletion_status": row["deletion_status"],
                             "steps_json": json.dumps(row["steps"], ensure_ascii=False, separators=(",", ":"))})


def write_uncertain(rows: list[dict[str, str]], path: Path = UNCERTAIN_OUTPUT) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "email", "request_text", "reason"])
        writer.writeheader()
        writer.writerows(rows)


def run(activity_mode: str = "confirmed", rebuild_observations: bool = True,
        print_counts: bool = True) -> list[dict[str, Any]]:
    context = load_context(rebuild_observations=rebuild_observations, print_counts=print_counts)
    rows, uncertain = predict_all(context, activity_mode)
    write_output(rows)
    write_uncertain(uncertain)
    print(f"Wrote {len(rows)} rows to {OUTPUT}")
    print(f"Uncertain request texts: {len(uncertain)} (see {UNCERTAIN_OUTPUT})")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--activity-mode", choices=("confirmed", "raw"), default="confirmed",
                        help="Use identity-confirmed activity candidates (default) or all time-window candidates")
    args = parser.parse_args()
    run(activity_mode=args.activity_mode, rebuild_observations=True, print_counts=True)


if __name__ == "__main__":
    main()
