"""Trace account and audit resource links for full and sample requests."""
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "code"))
import main  # noqa: E402


def sid(s):
    return tuple(s.get(k, "") for k in ("phase", "system_id", "resource_id", "operation", "state"))


ctx = main.load_context(rebuild_observations=False)
output = {r["case_id"]: r for r in csv.DictReader((ROOT / "output.csv").open(encoding="utf-8-sig"))}
stepmap = {cid: json.loads(r["steps_json"]) for cid, r in output.items()}
account_cases = {cid for cid, steps in stepmap.items() if any(s["system_id"] == "account_service" for s in steps)}
security_cases = {cid for cid, steps in stepmap.items() if any(s["system_id"] == "security_service" for s in steps)}
print("FULL ACCOUNT CASE COVERAGE", len(output), "with=", len(account_cases), "without=", len(output)-len(account_cases))
print("FULL SECURITY CASE COVERAGE", len(output), "with=", len(security_cases), "without=", len(output)-len(security_cases))

# Count identity/activity candidate account pairs among full requests that have no emitted account step.
no_account_candidates = []
nearby_account_rows = defaultdict(list)
for request in ctx["requests"]:
    if request["case_id"] in account_cases or output[request["case_id"]]["deletion_status"] == "NOT_APPLICABLE":
        continue
    user_text, identities = main.resolve_identity(request, ctx["identities"], ctx["audits"])
    user_ids = {v for v in user_text.split(";") if v}
    audit_at = main.parse_time(request.get("audit_at", ""))
    a_pairs, rows_by_pair = main.identity_candidate_pairs(identities, user_ids, ctx["observations"], audit_at, ctx["manifest"])
    b_pairs = main.get_activity_candidates(request, ctx["activities"], audit_at, identities, user_ids, rows_by_pair, "confirmed")
    pairs = sorted(p for p in a_pairs | b_pairs if p[0] == "account_service")
    if pairs:
        no_account_candidates.append((request, pairs, rows_by_pair))
    reported = main.parse_time(request.get("reported_at", ""))
    for activity in ctx["activities"]:
        event_at = main.parse_time(activity.get("event_time", ""))
        if (activity.get("source_system", "").casefold() == "deletion_worker" and
                activity.get("target_system", "").casefold() == "account_service" and
                activity.get("resource_id", "").casefold().startswith("account_") and event_at and audit_at and reported and
                event_at <= audit_at and abs(event_at-reported).total_seconds() <= 6*3600):
            nearby_account_rows[request["case_id"]].append(activity)
print("NO-STEP CASES WITH CONFIRMED ACCOUNT CANDIDATE", len(no_account_candidates))
for request, pairs, by_pair in no_account_candidates:
    print("CANDIDATE WITHOUT STEP", request["case_id"], pairs)
print("NO-STEP CASES WITH NEARBY ACCOUNT DELETION_WORKER ROW", len(nearby_account_rows))
print("NEARBY CASE IDS", sorted(nearby_account_rows))

# Scoring-only expected misses for account and security systems in the public sample.
sample_ctx = dict(ctx)
sample_ctx["requests"] = main.read_csv(ROOT / "dataset/sample_deletion_requests.csv")
sample_predictions, _ = main.predict_all(sample_ctx, "confirmed")
sample_by = {r["case_id"]: r for r in sample_predictions}
truth = {}
with (ROOT / "dataset/sample_output.csv").open(encoding="utf-8-sig", newline="") as f:
    for row in csv.DictReader(f):
        truth[row["case_id"]] = json.loads(row["steps_json"])
for system in ("account_service", "security_service"):
    misses = []
    for case_id, expected in truth.items():
        actual = Counter(sid(s) for s in sample_by[case_id]["steps"])
        remain = Counter(sid(s) for s in expected)
        remain.subtract(actual)
        misses.extend((case_id, key) for key, n in remain.items()
                      if key[1] == system for _ in range(max(0, n)))
    print(f"SAMPLE MISSING {system.upper()} STEPS", len(misses), "unique_cases=", len({c for c, _ in misses}))
    for case_id, key in misses:
        request = next(r for r in sample_ctx["requests"] if r["case_id"] == case_id)
        user_text, identities = main.resolve_identity(request, ctx["identities"], ctx["audits"])
        user_ids = {v for v in user_text.split(";") if v}
        audit_at = main.parse_time(request.get("audit_at", ""))
        a_pairs, rows_by_pair = main.identity_candidate_pairs(identities, user_ids, ctx["observations"], audit_at, ctx["manifest"])
        b_pairs = main.get_activity_candidates(request, ctx["activities"], audit_at, identities, user_ids, rows_by_pair, "confirmed")
        resource_pair = (key[1], key[2])
        print("MISS", case_id, "identity_set=", sorted(identities | user_ids), "expected=", key,
              "candidate=", resource_pair in (a_pairs | b_pairs))
        relevant = [o for o in ctx["observations"] if o["resource_id"] == key[2] and
                    (o["system_id"] == system or key[2].startswith("account_" if system == "account_service" else "audit_record_"))]
        for obs in relevant:
            capture = main.evidence_capture(obs["evidence_id"], ctx["manifest"])
            print("  OBS", obs["evidence_id"], capture, obs["system_id"], obs["normalized_state"],
                  "identity_match=", main.matching_identity_in_payload(obs["identifiers"], identities),
                  "user_ref_match=", main.user_reference_match(obs["identifiers"], user_ids), obs["identifiers"][:650])
        # Include every activity row that names the resource, or whose details contain a resolved identifier.
        activity_hits = [a for a in ctx["activities"] if
                         a.get("resource_id", "").casefold() == key[2].casefold() or
                         any(v and v.casefold() in json.dumps(a, ensure_ascii=False).casefold()
                             for v in identities | user_ids)]
        for activity in activity_hits:
            print("  ACT", activity)
