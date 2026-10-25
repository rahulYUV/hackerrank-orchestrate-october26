"""Join CLASSIFY_REQUEST account resources to request identities via evidence."""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "code"))
import main  # noqa: E402

ctx = main.load_context(rebuild_observations=False)
pred = {r["case_id"]: r for r in csv.DictReader((ROOT / "output.csv").open(encoding="utf-8-sig"))}
requests = ctx["requests"]
classify = [r for r in ctx["activities"] if r.get("event_type") == "CLASSIFY_REQUEST"]
for activity in classify:
    resource = activity.get("resource_id", "")
    observations = [r for r in ctx["observations"] if r["resource_id"] == resource]
    matches = []
    for request in requests:
        user_ids, values = main.resolve_identity(request, ctx["identities"], ctx["audits"])
        if any(main.matching_identity_in_payload(o["identifiers"], values) or
               main.user_reference_match(o["identifiers"], set(user_ids.split(";"))) for o in observations):
            matches.append(request)
    na_matches = [r for r in matches if pred.get(r["case_id"], {}).get("deletion_status") == "NOT_APPLICABLE"]
    print("CLASSIFY", activity["activity_id"], "account=", resource, "event_time=", activity["event_time"])
    print("  details=", activity.get("details", ""))
    for obs in observations:
        print("  OBS", obs["evidence_id"], obs["captured_at"], obs["system_id"], obs["normalized_state"], obs["identifiers"])
    print("  LINKED CASES", [(r["case_id"], r.get("email", ""), r.get("request_text", "")) for r in matches])
    print("  LINKED NOT_APPLICABLE", [r["case_id"] for r in na_matches])
