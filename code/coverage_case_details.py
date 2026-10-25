"""Produce auditable rows for selected no-account cases and no-security cases."""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "code"))
import main  # noqa: E402

ctx = main.load_context(rebuild_observations=False)
out = {r["case_id"]: r for r in csv.DictReader((ROOT / "output.csv").open(encoding="utf-8-sig"))}
all_ids = sorted(ctx["requests"], key=lambda r: int(r["case_id"].split("_")[-1]))

missing_account = []
for req in all_ids:
    steps = json.loads(out[req["case_id"]]["steps_json"])
    if out[req["case_id"]]["deletion_status"] == "NOT_APPLICABLE" or any(s["system_id"] == "account_service" for s in steps):
        continue
    user_text, values = main.resolve_identity(req, ctx["identities"], ctx["audits"])
    user_ids = set(user_text.split(";")) - {""}
    audit = main.parse_time(req.get("audit_at", ""))
    linked_obs = []
    for obs in ctx["observations"]:
        if not (obs["resource_id"].casefold().startswith("account_") or obs["system_id"].casefold() == "account_service"):
            continue
        capture = main.evidence_capture(obs["evidence_id"], ctx["manifest"])
        if audit and capture and capture <= audit and (main.matching_identity_in_payload(obs["identifiers"], values) or
                                                       main.user_reference_match(obs["identifiers"], user_ids)):
            linked_obs.append(obs)
    reported = main.parse_time(req.get("reported_at", ""))
    activity_rows = []
    for row in ctx["activities"]:
        when = main.parse_time(row.get("event_time", ""))
        if (row.get("target_system", "").casefold() == "account_service" and
                row.get("resource_id", "").casefold().startswith("account_") and when and audit and reported and
                when <= audit and abs(when-reported).total_seconds() <= 6*3600 and
                (row.get("event_type", "").upper() == "DELETE_RECORD" or any(v and v.casefold() in json.dumps(row, ensure_ascii=False).casefold() for v in values | user_ids))):
            activity_rows.append(row)
    missing_account.append((req, user_ids | values, linked_obs, activity_rows))

no_evidence = [x for x in missing_account if not x[2] and not x[3]]
print("FULL MISSING ACCOUNT CASES", len(missing_account), "WITH NO IDENTITY-LINKABLE ACCOUNT OBSERVATION OR ACTIVITY ROW", len(no_evidence))
for req, ids, obs, activities in no_evidence[:8]:
    print("ACCOUNT GAP", req["case_id"], "identity_set=", sorted(ids), "account_observations=none", "eligible_account_activity=none")

# For security, separately inspect same-subject references even when the containing
# evidence file was captured after audit_at; they can explain a link but cannot prove state.
missing_security = []
for req in all_ids:
    steps = json.loads(out[req["case_id"]]["steps_json"])
    if out[req["case_id"]]["deletion_status"] == "NOT_APPLICABLE" or any(s["system_id"] == "security_service" for s in steps):
        continue
    user_text, values = main.resolve_identity(req, ctx["identities"], ctx["audits"])
    user_ids = set(user_text.split(";")) - {""}
    audit = main.parse_time(req.get("audit_at", ""))
    refs = []
    for obs in ctx["observations"]:
        if not (obs["resource_id"].casefold().startswith("audit_record_") or obs["system_id"].casefold() == "security_service"):
            continue
        if main.matching_identity_in_payload(obs["identifiers"], values) or main.user_reference_match(obs["identifiers"], user_ids):
            capture = main.evidence_capture(obs["evidence_id"], ctx["manifest"])
            refs.append((obs, capture, bool(capture and audit and capture <= audit),
                         main.user_reference_match(obs["identifiers"], user_ids)))
    if refs:
        missing_security.append((req, user_ids | values, refs))
print("FULL NO-SECURITY CASES WITH A SUBJECT-REFERENCE OBSERVATION (ANY CAPTURE TIME)", len(missing_security))
for req, ids, refs in missing_security[:8]:
    print("SECURITY GAP", req["case_id"], "identity_set=", sorted(ids))
    for obs, capture, eligible, stable_ref in refs:
        print("  OBS", obs["evidence_id"], obs["resource_id"], obs["system_id"], "manifest_capture=", capture,
              "at_or_before_audit=", eligible, "stable_ref_match=", stable_ref,
              "payload=", obs["identifiers"][:400])
