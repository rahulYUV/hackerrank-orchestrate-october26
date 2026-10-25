#!/usr/bin/env python3
"""Measure resource discovery strategies against the 32 public sample cases."""

from __future__ import annotations

import csv
from functools import lru_cache
import json
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
OBS_DB = ROOT / "code" / "observations.sqlite"
OUT = ROOT / "code"
SAMPLE_IDS = [f"case_{i:02d}" for i in range(1, 33)]
WINDOWS = (1, 6, 24)
ID_FIELDS = {"email", "phone", "email_hash", "email_sha256", "user_id", "customer_reference", "subject_reference"}
IDENTITY_AUDIT_FIELDS = {"email", "phone", "email_hash", "email_sha256"}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def norm(value: Any) -> str:
    text = str(value or "").strip()
    if text.casefold() in {"", "null", "none", "n/a", "unknown"}:
        return ""
    return text


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def pairs_from_steps(steps_json: str) -> tuple[set[tuple[str, str]], dict[tuple[str, str], set[str]]]:
    pairs: set[tuple[str, str]] = set()
    cited: dict[tuple[str, str], set[str]] = defaultdict(set)
    for step in json.loads(steps_json):
        pair = (norm(step.get("system_id")), norm(step.get("resource_id")))
        if not pair[0] or not pair[1]:
            continue
        pairs.add(pair)
        evidence_id = norm(step.get("evidence_id"))
        if evidence_id:
            cited[pair].add(evidence_id)
    return pairs, cited


def nested_objects(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            if isinstance(child, (dict, list)):
                yield from nested_objects(child)
            elif isinstance(child, str) and child[:1] in "{[":
                try:
                    yield from nested_objects(json.loads(child))
                except (json.JSONDecodeError, TypeError):
                    pass
    elif isinstance(value, list):
        for child in value:
            yield from nested_objects(child)


def identifier_tokens(payload: Any) -> set[str]:
    result: set[str] = set()
    for obj in nested_objects(payload):
        for key, value in obj.items():
            if str(key).casefold() in ID_FIELDS:
                token = norm(value).casefold()
                if token:
                    result.add(token)
    return result


def customer_references(payload: Any) -> set[str]:
    result: set[str] = set()
    for obj in nested_objects(payload):
        for key, value in obj.items():
            if str(key).casefold() in {"customer_reference", "customer_ref"}:
                token = norm(value).casefold()
                if token:
                    result.add(token)
    return result


def resolve_identities(request: dict[str, str], identities: list[dict[str, str]], audit: list[dict[str, str]]) -> tuple[str, set[str]]:
    request_email = norm(request["email"]).casefold()
    users: set[str] = set()
    for row in identities:
        if norm(row.get("email")).casefold() == request_email:
            users.add(norm(row.get("user_id")))
    for row in audit:
        if norm(row.get("field_name")).casefold() == "email":
            if request_email in {norm(row.get("old_value")).casefold(), norm(row.get("new_value")).casefold()}:
                users.add(norm(row.get("user_id")))
    users.discard("")

    values: set[str] = set(users)
    for row in identities:
        if norm(row.get("user_id")) in users:
            for field in ("email", "phone", "email_hash"):
                value = norm(row.get(field)).casefold()
                if value:
                    values.add(value)
    for row in audit:
        if norm(row.get("user_id")) in users and norm(row.get("field_name")).casefold() in IDENTITY_AUDIT_FIELDS:
            for field in ("old_value", "new_value"):
                value = norm(row.get(field)).casefold()
                if value:
                    values.add(value)
    return ";".join(sorted(users)), values


def build_obs_rows(db: sqlite3.Connection) -> list[dict[str, Any]]:
    db.row_factory = sqlite3.Row
    return [dict(row) for row in db.execute(
        "SELECT evidence_id,captured_at,system_id,resource_id,category,state,normalized_state,identifiers FROM observations"
    )]


def actor_activity(activity: list[dict[str, str]]) -> list[dict[str, Any]]:
    rows = []
    for row in activity:
        actor = norm(row.get("source_system")).casefold()
        if actor not in {"deletion_worker", "privacy_intake"}:
            continue
        resource, system = norm(row.get("resource_id")), norm(row.get("target_system"))
        if not resource or not system or not norm(row.get("event_time")):
            continue
        rows.append({**row, "_pair": (system, resource), "_time": parse_time(row["event_time"])})
    return rows


def activity_pairs(rows: list[dict[str, Any]], reported_at: datetime, hours: int, window: str) -> set[tuple[str, str]]:
    delta = timedelta(hours=hours)
    result = set()
    for row in rows:
        diff = reported_at - row["_time"]
        if window == "before":
            eligible = timedelta(0) <= diff <= delta
        else:
            eligible = abs(diff) <= delta
        if eligible:
            result.add(row["_pair"])
    return result


def metric(expected: set[tuple[str, str]], found: set[tuple[str, str]]) -> tuple[int, int, int, float, float]:
    tp = len(expected & found)
    fp = len(found - expected)
    fn = len(expected - found)
    precision = tp / len(found) if found else 0.0
    recall = tp / len(expected) if expected else 0.0
    return tp, fp, fn, precision, recall


def table_system(table: str) -> str:
    name = table.casefold()
    mappings = (
        (("analytics", "telemetry"), "analytics_platform"),
        (("search", "index"), "search_service"),
        (("support", "ticket", "message", "attachment"), "support_platform"),
        (("export",), "export_service"),
        (("backup", "archive"), "backup_service"),
        (("connector", "flow", "integration"), "integration_service"),
        (("audit", "security"), "security_service"),
        (("identity", "tombstone"), "identity_service"),
        (("account", "profile"), "account_service"),
    )
    for fragments, system in mappings:
        if any(fragment in name for fragment in fragments):
            return system
    return ""


@lru_cache(maxsize=None)
def literal_occurrences(resource_id: str) -> list[tuple[str, str]]:
    """Find literal occurrences throughout dataset files; binary content is byte-scanned."""
    needle = resource_id.encode("ascii", errors="ignore").lower()
    found: list[tuple[str, str]] = []
    for path in sorted(DATA.rglob("*")):
        if not path.is_file():
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        has_literal = needle in raw.lower()
        if not has_literal and path.suffix.lower() != ".pdf":
            continue
        rel = path.relative_to(ROOT).as_posix()
        text = raw.decode("utf-8-sig", errors="replace")
        if path.suffix.lower() == ".pdf":
            try:
                from pypdf import PdfReader  # type: ignore
                text = "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
            except Exception:
                pass
        if not has_literal and resource_id.casefold() not in text.casefold():
            continue
        matched = False
        for line_no, line in enumerate(text.splitlines(), 1):
            if resource_id.casefold() in line.casefold():
                excerpt = re.sub(r"\s+", " ", line.strip())[:260]
                found.append((rel, f"line {line_no}: {excerpt}"))
                matched = True
        if not matched:
            offsets = [m.start() for m in re.finditer(re.escape(needle), raw.lower())]
            for offset in offsets[:5]:
                found.append((rel, f"binary byte offset {offset}"))
    return found


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    requests = read_csv(DATA / "sample_deletion_requests.csv")
    identities = read_csv(DATA / "user_identities.csv")
    audit = read_csv(DATA / "user_audit_log.csv")
    activity_rows = actor_activity(read_csv(DATA / "system_activity.csv"))
    manifest = {r["file_id"]: r for r in read_csv(DATA / "evidence_files.csv")}
    manifest_by_path = {r["file_path"].replace("\\", "/"): r["file_id"] for r in manifest.values()}
    requests_by_id = {r["case_id"]: r for r in requests}
    outputs = {r["case_id"]: r for r in read_csv(DATA / "sample_output.csv")}
    with sqlite3.connect(OBS_DB) as db:
        observations = build_obs_rows(db)
        sql_snapshots = {r[0]: {"captured_at": r[1], "tables": json.loads(r[2])}
                         for r in db.execute("SELECT evidence_id,captured_at,tables FROM sql_snapshots")}

    obs_by_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in observations:
        pair = (norm(row["system_id"]), norm(row["resource_id"]))
        if all(pair):
            obs_by_pair[pair].append(row)

    per_case_metrics: list[dict[str, Any]] = []
    overall_preds: dict[str, dict[str, set[tuple[str, str]]]] = {}
    expected_by_case: dict[str, set[tuple[str, str]]] = {}
    cites_by_case: dict[str, dict[tuple[str, str], set[str]]] = {}
    identities_by_case: dict[str, tuple[str, set[str]]] = {}
    resource_audit: list[dict[str, Any]] = []
    identity_resolution_failures: list[str] = []

    for case_id in SAMPLE_IDS:
        request = requests_by_id[case_id]
        expected, cites = pairs_from_steps(outputs[case_id]["steps_json"])
        expected_by_case[case_id], cites_by_case[case_id] = expected, cites
        user_ids, identity_values = resolve_identities(request, identities, audit)
        identities_by_case[case_id] = (user_ids, identity_values)
        if not user_ids:
            identity_resolution_failures.append(case_id)

        identity_needles = sorted(identity_values, key=len, reverse=True)
        a_found: set[tuple[str, str]] = set()
        obs_payload_by_pair: dict[tuple[str, str], list[Any]] = defaultdict(list)
        for row in observations:
            pair = (norm(row["system_id"]), norm(row["resource_id"]))
            payload_text = str(row["identifiers"]).casefold()
            if pair[0] and pair[1]:
                obs_payload_by_pair[pair].append(json.loads(row["identifiers"]))
                if any(needle in payload_text for needle in identity_needles):
                    a_found.add(pair)

        reported = parse_time(request["reported_at"])
        b_preds: dict[str, set[tuple[str, str]]] = {}
        for hours in WINDOWS:
            for window in ("before", "symmetric"):
                name = f"B_{hours}h_{window}"
                b_preds[name] = activity_pairs(activity_rows, reported, hours, window)

        strategies: dict[str, set[tuple[str, str]]] = {"A_identity": a_found}
        for b_name, b_found in b_preds.items():
            strategies[b_name] = b_found
            strategies[f"C_union_{b_name[2:]}"] = a_found | b_found

            # One-hop: observations sharing customer_reference or identifier values
            # with any resource reached by A or this B window.
            seeds = a_found | b_found
            seed_refs: set[str] = set()
            seed_tokens: set[str] = set()
            for pair in seeds:
                for payload in obs_payload_by_pair.get(pair, ()):
                    seed_refs.update(customer_references(payload))
                    seed_tokens.update(identifier_tokens(payload))
            expanded = set(a_found | b_found)
            for row in observations:
                pair = (norm(row["system_id"]), norm(row["resource_id"]))
                if not all(pair):
                    continue
                payload = json.loads(row["identifiers"])
                if customer_references(payload) & seed_refs or identifier_tokens(payload) & seed_tokens:
                    expanded.add(pair)
            strategies[f"C_union_{b_name[2:]}_1hop"] = expanded

        overall_preds[case_id] = strategies
        for strategy, found in strategies.items():
            tp, fp, fn, precision, recall = metric(expected, found)
            per_case_metrics.append({
                "case_id": case_id, "strategy": strategy,
                "expected_count": len(expected), "found_count": len(found),
                "true_positive": tp, "false_positive": fp, "false_negative": fn,
                "precision": f"{precision:.6f}", "recall": f"{recall:.6f}",
            })

        audit_at = parse_time(request["audit_at"])
        scope_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
        for row in observations:
            if not row["resource_id"] and row["normalized_state"] == "ABSENT":
                system = norm(row["system_id"])
                category = norm(row["category"])
                if system and table_system(category) == system:
                    for pair in expected:
                        if pair[0] == system:
                            scope_sources[pair].add(row["evidence_id"])
        for pair in expected:
            observed_ids = {r["evidence_id"] for r in obs_by_pair.get(pair, [])}
            literal_evidence_ids: set[str] = set()
            literal_paths: set[str] = set()
            for rel_path, _context in literal_occurrences(pair[1]):
                if rel_path.startswith("dataset/evidence/"):
                    literal_paths.add(rel_path)
                    file_id = manifest_by_path.get(rel_path.removeprefix("dataset/"))
                    if file_id:
                        literal_evidence_ids.add(file_id)
            resource_ids = observed_ids | literal_evidence_ids
            relevant_scope_ids = set(scope_sources[pair])
            # Count a SQL scope as case-relevant only if it is the cited file for
            # this resource and contains a table mapped to the expected system.
            cited = sorted(cites.get(pair, set()))
            for evidence_id in cited:
                snap = sql_snapshots.get(evidence_id)
                if snap and any(table_system(table) == pair[0] for table in snap["tables"]):
                    relevant_scope_ids.add(evidence_id)
            source_ids = resource_ids | relevant_scope_ids
            eligible = sorted(
                (e for e in resource_ids if e in manifest and parse_time(manifest[e]["captured_at"]) <= audit_at),
                key=lambda e: (manifest[e]["captured_at"], e),
            )
            latest = eligible[-1] if eligible else ""
            latest_time = manifest[latest]["captured_at"] if latest else ""
            latest_ids = [e for e in eligible if manifest[e]["captured_at"] == latest_time] if latest else []
            cited_latest = "not_assessable_no_resource_file" if cited and not latest else ("" if not cited else str(bool(set(latest_ids) & set(cited))).lower())
            cited_cutoff = [e for e in cited if e in manifest and parse_time(manifest[e]["captured_at"]) <= audit_at]
            if set(cited) & resource_ids:
                cited_support_type = "resource_literal_or_observation"
            elif set(cited) & relevant_scope_ids:
                cited_support_type = "parsed_absence_scope"
            elif cited:
                cited_support_type = "cited_file_not_textually_linked"
            else:
                cited_support_type = "no_cited_evidence"
            resource_audit.append({
                "case_id": case_id, "system_id": pair[0], "resource_id": pair[1],
                "cited_evidence_ids": ";".join(cited),
                "evidence_ids_with_parsed_resource_observation": ";".join(sorted(observed_ids)),
                "evidence_ids_with_literal_resource_in_evidence_file": ";".join(sorted(literal_evidence_ids)),
                "evidence_paths_with_literal_resource": ";".join(sorted(literal_paths)),
                "evidence_files_with_resource": ";".join(sorted(resource_ids)),
                "matching_system_scope_evidence_ids": ";".join(sorted(relevant_scope_ids)),
                "evidence_files_with_resource_or_scope": ";".join(sorted(source_ids)),
                "latest_evidence_id_at_or_before_audit": latest,
                "latest_evidence_ids_at_or_before_audit": ";".join(latest_ids),
                "latest_capture_at_or_before_audit": latest_time,
                "cited_evidence_at_or_before_audit": ";".join(cited_cutoff),
                "cited_support_type": cited_support_type,
                "cited_file_is_latest_resource_capture": cited_latest,
                "audit_at": request["audit_at"],
            })

    # Per-case and overall score artifacts.
    write_csv(OUT / "discovery_case_metrics.csv", list(per_case_metrics[0]), per_case_metrics)
    strategy_names = list(overall_preds[SAMPLE_IDS[0]].keys())
    overall_rows: list[dict[str, Any]] = []
    for strategy in strategy_names:
        totals = {"tp": 0, "fp": 0, "fn": 0}
        case_ps, case_rs = [], []
        for case_id in SAMPLE_IDS:
            expected = expected_by_case[case_id]
            found = overall_preds[case_id][strategy]
            tp, fp, fn, precision, recall = metric(expected, found)
            totals["tp"] += tp; totals["fp"] += fp; totals["fn"] += fn
            case_ps.append(precision); case_rs.append(recall)
        micro_p = totals["tp"] / (totals["tp"] + totals["fp"]) if totals["tp"] + totals["fp"] else 0.0
        micro_r = totals["tp"] / (totals["tp"] + totals["fn"]) if totals["tp"] + totals["fn"] else 0.0
        overall_rows.append({
            "strategy": strategy, "micro_precision": f"{micro_p:.6f}", "micro_recall": f"{micro_r:.6f}",
            "macro_precision": f"{sum(case_ps)/len(case_ps):.6f}",
            "macro_recall": f"{sum(case_rs)/len(case_rs):.6f}",
            "true_positive": totals["tp"], "false_positive": totals["fp"], "false_negative": totals["fn"],
        })
    write_csv(OUT / "discovery_overall_metrics.csv", list(overall_rows[0]), overall_rows)
    write_csv(OUT / "discovery_resource_audit.csv", list(resource_audit[0]), resource_audit)

    missing_rows: list[dict[str, Any]] = []
    missing_markdown = ["# Expected resources missed by all tested strategies", ""]
    for case_id in SAMPLE_IDS:
        found_any = set().union(*overall_preds[case_id].values())
        for system_id, resource_id in sorted(expected_by_case[case_id] - found_any):
            occurrences = literal_occurrences(resource_id)
            missing_rows.append({
                "case_id": case_id, "system_id": system_id, "resource_id": resource_id,
                "dataset_occurrence_count": len(occurrences),
                "dataset_occurrences": " || ".join(f"{path}: {context}" for path, context in occurrences),
            })
            missing_markdown.append(f"## {case_id}: `{system_id}` / `{resource_id}`")
            if occurrences:
                missing_markdown.extend(f"- `{path}` — {context}" for path, context in occurrences)
            else:
                missing_markdown.append("- No literal occurrence found in dataset files (PDF/PNG content was byte-scanned; images were not OCR'd).")
            missing_markdown.append("")
    write_csv(OUT / "discovery_missing_resources.csv",
              ["case_id", "system_id", "resource_id", "dataset_occurrence_count", "dataset_occurrences"], missing_rows)
    (OUT / "discovery_missing_resources.md").write_text("\n".join(missing_markdown) + "\n", encoding="utf-8")

    citations = []
    for case_id in SAMPLE_IDS:
        request = requests_by_id[case_id]
        cits = sorted({e for ids in cites_by_case[case_id].values() for e in ids})
        resources = [r for r in resource_audit if r["case_id"] == case_id]
        containing = sorted({e for r in resources for e in r["evidence_files_with_resource"].split(";") if e})
        latest_ids = sorted({e for r in resources for e in r["latest_evidence_ids_at_or_before_audit"].split(";") if e})
        citation_rows = [r for r in resources if r["cited_evidence_ids"]]
        latest_count = sum(r["cited_file_is_latest_resource_capture"] == "true" for r in citation_rows)
        stale_count = sum(r["cited_file_is_latest_resource_capture"] == "false" for r in citation_rows)
        scope_only_count = sum(r["cited_file_is_latest_resource_capture"] == "not_assessable_no_resource_file" for r in citation_rows)
        citations.append({
            "case_id": case_id, "audit_at": request["audit_at"],
            "sample_cited_evidence_ids": ";".join(cits),
            "evidence_ids_containing_expected_resources": ";".join(containing),
            "latest_capture_ids_at_or_before_audit": ";".join(latest_ids),
            "cited_resource_pairs_latest": latest_count,
            "cited_resource_pairs_not_latest": stale_count,
            "cited_resource_pairs_without_direct_resource_capture": scope_only_count,
        })
    write_csv(OUT / "discovery_citation_summary.csv", list(citations[0]), citations)

    cited_pair_statuses = Counter(
        row["cited_file_is_latest_resource_capture"]
        for row in resource_audit if row["cited_evidence_ids"]
    )

    lines = [
        "# Sample resource discovery measurement", "",
        "Ground truth is the unique `(system_id, resource_id)` set across every step in each row of `dataset/sample_output.csv`, including proposed remediation and future verification targets. `A` uses literal case-insensitive substring matching against parsed observation `identifiers`. `B` filters activity rows where `source_system` is `deletion_worker` or `privacy_intake`, scores `(target_system, resource_id)`, and uses before-only or symmetric windows around `reported_at`. Precision is 0 when a strategy finds no pairs. Overall micro scores aggregate pair counts; macro scores average the 32 per-case scores.",
        "",
        "`C_union_*` is A union B. `C_union_*_1hop` adds observation pairs whose `customer_reference` or identifier token is shared with an A/B seed resource. The exact per-case precision/recall for every strategy is in `discovery_case_metrics.csv`; resource citation/capture details are in `discovery_resource_audit.csv` and `discovery_citation_summary.csv`.",
        "",
        f"Identity resolution failures: {', '.join(identity_resolution_failures) if identity_resolution_failures else 'none'}.",
        "",
        "## Overall precision and recall", "",
        "| Strategy | Micro precision | Micro recall | Macro precision | Macro recall | TP | FP | FN |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in overall_rows:
        lines.append(f"| {row['strategy']} | {float(row['micro_precision']):.3f} | {float(row['micro_recall']):.3f} | {float(row['macro_precision']):.3f} | {float(row['macro_recall']):.3f} | {row['true_positive']} | {row['false_positive']} | {row['false_negative']} |")
    lines.extend(["", "## Expected resources missed by every strategy", "",
                  f"Count: {len(missing_rows)}. See `discovery_missing_resources.md` for each resource and every literal dataset occurrence.", "",
                  "## Citation freshness counts", "",
                  f"Cited expected-resource pairs: {sum(cited_pair_statuses.values())}; latest direct resource capture: {cited_pair_statuses['true']}; cited but not latest: {cited_pair_statuses['false']}; latest direct capture not assessable because the resource ID is absent from searchable evidence content: {cited_pair_statuses['not_assessable_no_resource_file']}.", "",
                  "## Citation freshness", "",
                  "Resource-level citation freshness compares each cited `evidence_id` with the latest manifest capture at or before `audit_at` among evidence files where that resource ID occurs literally or as a parsed observation. Scope-only evidence for absent resources is reported separately; if no evidence file contains the resource ID, latest resource-capture status is not assessable from direct occurrences. The `cited_support_type` column distinguishes direct resource evidence, parsed empty-snapshot evidence, and citations not textually linked by this scan. PDF text extraction was unavailable in this runtime (neither `pypdf` nor PyMuPDF is installed), and PNGs were not OCR'd. See `discovery_resource_audit.csv` for per-pair file IDs, literal paths, citations, scope sources, and cutoff comparison.", ""])
    (OUT / "discovery_report.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"cases={len(SAMPLE_IDS)} expected_resource_pairs={sum(map(len, expected_by_case.values()))}")
    print(f"activity_rows_by_target_actor={len(activity_rows)} strategy_count={len(strategy_names)}")
    print(f"identity_resolution_failures={identity_resolution_failures}")
    print(f"expected_pairs_missed_by_all_strategies={len(missing_rows)}")
    print(f"reports={OUT / 'discovery_report.md'}; per_case={OUT / 'discovery_case_metrics.csv'}; citations={OUT / 'discovery_resource_audit.csv'}")


if __name__ == "__main__":
    main()
