"""Scoring-only experiment: nearest primary account worker event to reported_at."""
import sys
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "code"))
import main  # noqa: E402
import evaluate  # noqa: E402

ctx = main.load_context(rebuild_observations=False)
ctx["requests"] = main.read_csv(ROOT / "dataset/sample_deletion_requests.csv")
original = main.get_activity_candidates
chosen_by_case = {}


def nearest_candidate(request, activities, audit_at, identity_values, user_ids, rows_by_pair, mode):
    found = original(request, activities, audit_at, identity_values, user_ids, rows_by_pair, mode)
    reported = main.parse_time(request.get("reported_at", ""))
    if not reported:
        return found
    eligible = []
    for row in activities:
        when = main.parse_time(row.get("event_time", ""))
        if (row.get("source_system", "").casefold() == "deletion_worker" and
                row.get("target_system", "").casefold() == "account_service" and
                row.get("event_type", "").upper() == "DELETE_RECORD" and
                row.get("resource_id", "").casefold().startswith("account_") and when and when <= audit_at and
                abs(when-reported).total_seconds() <= 6*3600):
            eligible.append((abs(when-reported), row.get("resource_id", "")))
    if eligible:
        best = min(delta for delta, _ in eligible)
        resources = {resource for delta, resource in eligible if delta == best}
        if len(resources) == 1:
            found.add(("account_service", next(iter(resources))))
            chosen_by_case[request["case_id"]] = next(iter(resources))
    return found


main.get_activity_candidates = nearest_candidate
predictions, _ = main.predict_all(ctx, "confirmed")
truth = evaluate.load_truth()
scores = evaluate.score(predictions, truth, print_diffs=False)
print("nearest-link experiment:", {k: scores[k] for k in ("status_accuracy", "step_precision", "step_recall", "step_f1", "field_accuracy", "exact_sequence_rate", "tp", "fp", "fn")})
print("newly selected account resources:", len(chosen_by_case))
for case_id, resource in sorted(chosen_by_case.items()):
    expected_pairs = {s["resource_id"] for s in truth[case_id]["steps"] if s["system_id"] == "account_service"}
    actual_pairs = {s["resource_id"] for s in scores["pred"][case_id]["steps"] if s["system_id"] == "account_service"}
    print(case_id, resource, "expected_account_resources=", sorted(expected_pairs), "predicted=", sorted(actual_pairs))
