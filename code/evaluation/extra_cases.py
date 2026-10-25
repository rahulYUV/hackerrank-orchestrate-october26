#!/usr/bin/env python3
"""Generate and run three property-based cases against the production solver."""
from __future__ import annotations

import csv
import json
import sys
from datetime import timedelta
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
ROOT = CODE.parent
sys.path.insert(0, str(CODE))
import main  # noqa: E402

CASES_CSV = Path(__file__).with_name("extra_cases.csv")
RESULTS_MD = Path(__file__).with_name("extra_cases_results.md")
FIELDS = ("case_id", "email", "requested_at", "reported_status", "reported_at",
          "audit_at", "request_text", "scenario")


def iso(value) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_request(case_id: str, email: str, requested_at, reported_at, audit_at,
                 text: str, scenario: str) -> dict[str, str]:
    return {"case_id": case_id, "email": email, "requested_at": iso(requested_at),
            "reported_status": "COMPLETE", "reported_at": iso(reported_at),
            "audit_at": iso(audit_at), "request_text": text, "scenario": scenario}


def identity_material(identities: list[dict[str, str]], audits: list[dict[str, str]], uid: str):
    values = {uid.casefold()}
    for row in identities:
        if row.get("user_id") == uid:
            values.update(row.get(k, "").casefold() for k in ("email", "phone", "email_hash") if row.get(k))
    for row in audits:
        if row.get("user_id") == uid and row.get("field_name", "").casefold() in {"email", "phone", "email_hash", "email_sha256"}:
            values.update(row.get(k, "").casefold() for k in ("old_value", "new_value") if row.get(k))
    return {v for v in values if v}


def find_late_evidence_user(context: dict, excluded: set[str]):
    known_users = {r.get("user_id", "").casefold(): r.get("user_id", "")
                   for r in context["identities"] if r.get("user_id") and r.get("user_id") not in excluded}
    owner_keys = {"user_id", "subject_ref", "subject_reference", "correlation_key",
                  "customer_reference", "customer_ref", "subject_key"}
    by_user: dict[str, list[tuple[object, dict]]] = {}
    # Extract stable references once per observation, instead of repeatedly
    # scanning the full corpus once per identity.
    for row in context["observations"]:
        try:
            payload = json.loads(row.get("identifiers", "{}"))
        except (json.JSONDecodeError, TypeError):
            continue
        capture = main.evidence_capture(row.get("evidence_id", ""), context["manifest"])
        if not capture:
            continue
        for obj in main.nested_payloads(payload):
            for key, value in obj.items():
                if str(key).casefold() not in owner_keys:
                    continue
                values = value if isinstance(value, list) else [value]
                for value in values:
                    uid = known_users.get(str(value).casefold()) if value is not None else None
                    if uid:
                        by_user.setdefault(uid, []).append((capture, row))
    candidates = []
    for uid, matches in by_user.items():
        matches.sort(key=lambda item: item[0])
        candidates.append((matches[0][0], uid, matches))
    candidates.sort(key=lambda item: (item[0], item[1]))
    if not candidates:
        raise AssertionError("Could not find an identity with linked captured evidence")
    return candidates[0]


def generate_cases(context: dict) -> tuple[list[dict[str, str]], dict[str, str]]:
    identities, audits = context["identities"], context["audits"]
    current_emails = {r.get("email", "").casefold() for r in identities if r.get("email")}
    historical = []
    for row in audits:
        if row.get("field_name", "").casefold() != "email":
            continue
        old = row.get("old_value", "").strip()
        if "@" not in old or old.casefold() == row.get("new_value", "").casefold():
            continue
        if old.casefold() in current_emails:
            continue
        historical.append((row.get("user_id", ""), old, row.get("event_time", "")))
    historical.sort(key=lambda x: (x[2], x[0], x[1]))
    if not historical:
        raise AssertionError("No historical email old_value found")
    hist_uid, hist_email, _ = historical[0]

    other = next((r for r in identities if r.get("user_id") != hist_uid and r.get("email")), None)
    if not other:
        raise AssertionError("Could not select a separate identity for the non-English case")
    third_capture, third_uid, third_matches = find_late_evidence_user(context, {hist_uid, other["user_id"]})
    late_matches = [(capture, row) for capture, row in third_matches if capture > third_capture - timedelta(seconds=1)]
    if not late_matches:
        raise AssertionError("Selected subject has no linked evidence after the proposed cutoff")

    request_time = main.parse_time("2026-10-01T09:00:00Z")
    cases = [
        make_request("extra_historical_email_01", hist_email, request_time,
                     request_time + timedelta(hours=1), request_time + timedelta(days=1),
                     "Please erase my account and disconnect every remaining copy of my personal data.",
                     "historical_email_identity"),
        make_request("extra_keep_update_de_02", other["email"], request_time,
                     request_time + timedelta(hours=1), request_time + timedelta(days=1),
                     "Bitte behalten Sie mein Konto und aktualisieren Sie meine Anschrift; ich möchte auch meine Telefonnummer ändern.",
                     "non_deletion_keep_and_update_german"),
        make_request("extra_early_audit_03", next(r["email"] for r in identities if r.get("user_id") == third_uid),
                     third_capture - timedelta(days=2), third_capture - timedelta(days=1),
                     third_capture - timedelta(seconds=1),
                     "I request erasure of my account and its copies across the service.",
                     "audit_cutoff_before_subject_evidence"),
    ]
    metadata = {"historical_user_id": hist_uid, "historical_email": hist_email,
                "german_user_id": other["user_id"], "cutoff_user_id": third_uid,
                "cutoff_capture_at": iso(third_capture),
                "cutoff_late_observation_count": str(len(late_matches))}
    return cases, metadata


def run() -> None:
    # The request rows are generated from participant-facing identity sources;
    # sample_output.csv is not read anywhere in this script.
    context = main.load_context(rebuild_observations=False)
    cases, meta = generate_cases(context)
    with CASES_CSV.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(cases)

    test_context = main.load_context(rebuild_observations=False, requests_path=CASES_CSV)
    predictions, _ = main.predict_all(test_context, "confirmed")
    by_case = {r["case_id"]: r for r in predictions}
    request_by_case = {r["case_id"]: r for r in cases}

    hist = request_by_case["extra_historical_email_01"]
    hist_ids, _ = main.resolve_identity(hist, context["identities"], context["audits"])
    hist_uid_found = meta["historical_user_id"] in set(hist_ids.split(";"))
    assert hist_uid_found, "Historical old_value email did not resolve to its user_id"

    keep = by_case["extra_keep_update_de_02"]
    assert keep["deletion_status"] == "NOT_APPLICABLE" and keep["steps"] == [], \
        "German keep/update request must be NOT_APPLICABLE with no steps"

    cutoff = request_by_case["extra_early_audit_03"]
    cutoff_at = main.parse_time(cutoff["audit_at"])
    cited = []
    for step in by_case[cutoff["case_id"]]["steps"]:
        evidence_id = step.get("evidence_id", "")
        if evidence_id:
            capture = main.evidence_capture(evidence_id, context["manifest"])
            cited.append((evidence_id, capture))
            assert capture is not None and capture <= cutoff_at, \
                f"Cited evidence {evidence_id} is missing capture metadata or after audit_at"
    late_linked_count = int(meta["cutoff_late_observation_count"])
    assert late_linked_count > 0, "Cutoff case does not exercise later linked evidence"

    lines = [
        "# Synthetic property cases",
        "",
        "Generated from `user_identities.csv`, `user_audit_log.csv`, the evidence manifest, and parsed participant evidence.",
        "No expected step arrays were authored; predictions below come from `main.predict_all`.",
        "",
        "| Case | Property | Solver status | Assertion |",
        "|---|---|---|---|",
        f"| extra_historical_email_01 | Historical email resolves to user_id `{meta['historical_user_id']}` | {by_case['extra_historical_email_01']['deletion_status']} | {'PASS' if hist_uid_found else 'FAIL'} |",
        f"| extra_keep_update_de_02 | German keep-account/update request has no steps | {keep['deletion_status']} | PASS |",
        f"| extra_early_audit_03 | Cutoff is before linked evidence captured at {meta['cutoff_capture_at']} ({late_linked_count} linked observations) | {by_case['extra_early_audit_03']['deletion_status']} | PASS: no cited capture after cutoff |",
        "",
        "## Solver-produced steps",
        "",
    ]
    for case in cases:
        result = by_case[case["case_id"]]
        lines.append(f"### {case['case_id']}")
        lines.append("")
        lines.append(f"Status: `{result['deletion_status']}`")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(result["steps"], ensure_ascii=False, indent=2))
        lines.append("```")
        lines.append("")
    lines.extend([
        "## Citation cutoff check",
        "",
        f"Case `extra_early_audit_03` had {late_linked_count} linked observation(s) captured after its audit cutoff.",
        f"Citations in the solver-produced result: {json.dumps([(eid, iso(ts) if ts else None) for eid, ts in cited])}.",
        "Assertion: every non-empty citation has manifest capture time at or before `audit_at`.",
        "",
    ])
    RESULTS_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {CASES_CSV.relative_to(ROOT)} ({len(cases)} rows)")
    print(f"Wrote {RESULTS_MD.relative_to(ROOT)}")
    print("PASS: historical email resolved to its user_id")
    print("PASS: German keep/update request => NOT_APPLICABLE with []")
    print(f"PASS: early cutoff had {late_linked_count} linked later observations; no later citation")


if __name__ == "__main__":
    run()
