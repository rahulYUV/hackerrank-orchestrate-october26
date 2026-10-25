"""Validate output.csv shape, ordering, citations, and audit-time cutoffs."""
from __future__ import annotations

import csv
import json
from pathlib import Path

import main


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output.csv"
REQUESTS = ROOT / "dataset" / "deletion_requests.csv"
MANIFEST = ROOT / "dataset" / "evidence_files.csv"
EXPECTED_COLUMNS = ["case_id", "deletion_status", "steps_json"]


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        return reader.fieldnames or [], list(reader)


def main_validate() -> int:
    errors: list[str] = []
    columns, rows = read_csv(OUTPUT)
    if columns != EXPECTED_COLUMNS:
        errors.append(f"header must be {EXPECTED_COLUMNS!r}, got {columns!r}")

    requests = {r["case_id"]: r for r in read_csv(REQUESTS)[1]}
    manifest_rows = read_csv(MANIFEST)[1]
    manifest = {r["file_id"]: r for r in manifest_rows}
    case_ids = [r.get("case_id", "") for r in rows]
    expected_ids = sorted(requests)
    if len(rows) != 518:
        errors.append(f"expected 518 output rows, got {len(rows)}")
    if case_ids != sorted(case_ids):
        errors.append("output rows are not sorted by case_id")
    if len(case_ids) != len(set(case_ids)):
        errors.append("output contains duplicate case_id values")
    if case_ids != expected_ids:
        errors.append("output case_id set/order does not match deletion_requests.csv")

    phase_order = main.PHASE_ORDER
    checked_steps = 0
    for row in rows:
        cid = row.get("case_id", "")
        try:
            steps = json.loads(row.get("steps_json", ""))
        except json.JSONDecodeError as exc:
            errors.append(f"{cid}: invalid steps_json ({exc})")
            continue
        if not isinstance(steps, list):
            errors.append(f"{cid}: steps_json is not an array")
            continue
        if [s.get("step_no") for s in steps if isinstance(s, dict)] != list(range(1, len(steps) + 1)):
            errors.append(f"{cid}: step_no values are not consecutive from 1")
        sort_keys = []
        for step in steps:
            checked_steps += 1
            if not isinstance(step, dict):
                errors.append(f"{cid}: a step is not a JSON object")
                continue
            phase = step.get("phase", "")
            operation = step.get("operation", "")
            if phase not in phase_order:
                errors.append(f"{cid}: invalid phase {phase!r}")
            if operation not in main.OPERATION_ORDER:
                errors.append(f"{cid}: invalid operation {operation!r}")
            sort_keys.append((phase_order.get(phase, 999), main.OPERATION_ORDER.get(operation, 999),
                              step.get("system_id", ""), step.get("resource_id", "")))
            evidence_id = step.get("evidence_id", "")
            if evidence_id:
                if evidence_id not in manifest:
                    errors.append(f"{cid}: unknown evidence_id {evidence_id!r}")
                else:
                    capture = main.parse_time(manifest[evidence_id].get("captured_at", ""))
                    audit_at = main.parse_time(requests.get(cid, {}).get("audit_at", ""))
                    if not capture:
                        errors.append(f"{cid}: evidence {evidence_id} has no valid captured_at")
                    elif audit_at and capture > audit_at:
                        errors.append(f"{cid}: evidence {evidence_id} captured after audit_at")
        if sort_keys != sorted(sort_keys):
            errors.append(f"{cid}: steps violate phase/operation/system/resource order")

    if errors:
        print(f"FAIL: {len(errors)} validation error(s); checked {checked_steps} steps")
        for error in errors:
            print(" -", error)
        return 1
    print(f"PASS: {len(rows)} sorted rows, {checked_steps} steps; JSON, numbering, phase/operation order, evidence IDs, and cutoffs valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_validate())
