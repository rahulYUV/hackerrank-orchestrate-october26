"""Score discovery hypotheses against public samples; truth is scoring-only."""
from __future__ import annotations

import csv
import re
import sys
from collections import Counter, defaultdict
from datetime import timedelta

import main
import evaluate


def resource_class(resource_id: str) -> str:
    m = re.match(r"([a-z]+(?:_[a-z]+)*)_", resource_id.casefold())
    prefix = m.group(1) if m else "other"
    return {"audit_record": "audit"}.get(prefix, prefix)


def activity_blocks(activities: list[dict[str, str]]) -> list[list[dict[str, str]]]:
    # Keep operational workers and the systems that execute/confirm their work.
    related = {"deletion_worker", "privacy_intake", "profile_service", "account_service",
               "support_platform", "security_service", "export_service", "integration_service",
               "backup_service"}
    rows = [r for r in activities if r.get("source_system", "").casefold() in related]
    rows.sort(key=lambda r: int(re.search(r"(\d+)$", r.get("activity_id", "0")).group(1)))
    blocks: list[list[dict[str, str]]] = []
    previous = None
    for row in rows:
        number = int(re.search(r"(\d+)$", row.get("activity_id", "0")).group(1))
        if not blocks or previous is None or number != previous + 1:
            blocks.append([])
        blocks[-1].append(row)
        previous = number
    return blocks


def block_pairs(request: dict[str, str], blocks: list[list[dict[str, str]]]) -> set[tuple[str, str]]:
    reported = main.parse_time(request.get("reported_at", ""))
    if not reported:
        return set()
    candidates = []
    for block in blocks:
        timed = [(main.parse_time(r.get("event_time", "")), r) for r in block]
        timed = [(t, r) for t, r in timed if t]
        if timed:
            distance = min(abs(t - reported) for t, _ in timed)
            candidates.append((distance, block))
    if not candidates:
        return set()
    block = min(candidates, key=lambda x: (x[0], min(r["activity_id"] for r in x[1])))[1]
    return {(r.get("target_system", ""), r.get("resource_id", "")) for r in block
            if r.get("target_system") and r.get("resource_id")}


def score_candidates(predicted: dict[str, set[tuple[str, str]]], truth: dict[str, dict]) -> None:
    expected: dict[str, set[tuple[str, str]]] = {}
    for case, answer in truth.items():
        expected[case] = {(s["system_id"], s["resource_id"]) for s in answer["steps"]}
    classes = sorted({resource_class(r) for resources in list(expected.values()) + list(predicted.values()) for _, r in resources})
    print("NEAREST BLOCK RESOURCE-PAIR METRICS (independent discovery rule)")
    for cls in classes:
        e = {(c, p) for c, pairs in expected.items() for p in pairs if resource_class(p[1]) == cls}
        a = {(c, p) for c, pairs in predicted.items() for p in pairs if resource_class(p[1]) == cls}
        tp = len(e & a)
        precision = f"{tp/len(a):.4f}" if a else "n/a"
        recall = f"{tp/len(e):.4f}" if e else "n/a"
        print(f"  {cls}: precision={precision} recall={recall} TP/pred/expected={tp}/{len(a)}/{len(e)}")


def metric_line(label: str, predictions: list[dict], truth: dict) -> dict:
    result = evaluate.score(predictions, truth, print_diffs=False)
    evaluate.show_scores(label, result)
    return result


def per_case_diff(before: list[dict], after: list[dict], detail: bool = False) -> None:
    old = {r["case_id"]: r for r in before}
    new = {r["case_id"]: r for r in after}
    stepid = evaluate.step_id
    for cid in sorted(new):
        b = Counter(map(stepid, old[cid]["steps"]))
        a = Counter(map(stepid, new[cid]["steps"]))
        added, removed = list((a - b).elements()), list((b - a).elements())
        if added or removed:
            if detail:
                print("  STEP_DIFF", cid, "added=", added, "removed=", removed)
            else:
                print("  STEP_DIFF", cid, "added_count=", len(added), "removed_count=", len(removed))


def main_audit() -> None:
    context = main.load_context(rebuild_observations=False)
    context["requests"] = main.read_csv(main.DATA / "sample_deletion_requests.csv")
    base, _ = main.predict_all(context, "confirmed")

    blocks = activity_blocks(context["activities"])
    block_predictions = {r["case_id"]: block_pairs(r, blocks) for r in context["requests"]}
    original_get_activity = main.get_activity_candidates
    def with_blocks(req, activities, audit, values, user_ids, rows, mode):
        return original_get_activity(req, activities, audit, values, user_ids, rows, mode) | block_predictions.get(req["case_id"], set())
    main.get_activity_candidates = with_blocks
    block_union, _ = main.predict_all(context, "confirmed")
    main.get_activity_candidates = original_get_activity

    original_identity = main.identity_candidate_pairs
    def late_ownership(values, user_ids, observations, audit, manifest):
        found, eligible = original_identity(values, user_ids, observations, audit, manifest)
        for row in observations:
            resource = main.clean(row.get("resource_id"))
            system = main.clean(row.get("system_id"))
            if not system or not resource:
                continue
            if main.matching_identity_in_payload(row.get("identifiers", ""), values) or main.user_reference_match(row.get("identifiers", ""), user_ids):
                found.add((system, resource))
        return found, eligible
    main.identity_candidate_pairs = late_ownership
    ownership, _ = main.predict_all(context, "confirmed")

    main.get_activity_candidates = with_blocks
    combined, _ = main.predict_all(context, "confirmed")
    main.identity_candidate_pairs = original_identity
    main.get_activity_candidates = original_get_activity

    # Public answers are loaded only after all prediction variants are built.
    truth = evaluate.load_truth()
    baseline_score = metric_line("Baseline", base, truth)
    score_candidates(block_predictions, truth)
    block_score = metric_line("Baseline + nearest block", block_union, truth)
    print("BLOCK UNION STEP DIFF SUMMARY:")
    per_case_diff(base, block_union)
    own_score = metric_line("Baseline + post-cutoff ownership links", ownership, truth)
    print("OWNERSHIP STEP CHANGES:")
    per_case_diff(base, ownership, detail=True)
    combined_score = metric_line("Baseline + ownership + nearest block", combined, truth)
    print("COMBINED STEP DIFF SUMMARY:")
    per_case_diff(base, combined)
    print("KEEP_CHECK block=", block_score["step_recall"] > baseline_score["step_recall"] and block_score["step_precision"] >= baseline_score["step_precision"],
          "ownership=", own_score["step_recall"] > baseline_score["step_recall"] and own_score["step_precision"] >= baseline_score["step_precision"],
          "combined=", combined_score["step_recall"] > baseline_score["step_recall"] and combined_score["step_precision"] >= baseline_score["step_precision"])


if __name__ == "__main__":
    main_audit()
