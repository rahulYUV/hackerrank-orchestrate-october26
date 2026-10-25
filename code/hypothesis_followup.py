"""Test one-to-one account activity matching and direct-state precedence."""
from __future__ import annotations

import re
import json
from collections import Counter
from datetime import timedelta

import main
import evaluate


def account_worker_events(activities: list[dict[str, str]]) -> list[dict[str, str]]:
    return [r for r in activities
            if r.get("source_system", "").casefold() == "deletion_worker"
            and r.get("event_type", "").upper() == "DELETE_RECORD"
            and r.get("target_system", "").casefold() == "account_service"
            and r.get("resource_id", "").casefold().startswith("account_")]


def global_mutual_matches(requests: list[dict[str, str]], activities: list[dict[str, str]]) -> dict[str, set[tuple[str, str]]]:
    events = account_worker_events(activities)
    cases = []
    for r in requests:
        reported, audit = main.parse_time(r.get("reported_at", "")), main.parse_time(r.get("audit_at", ""))
        if reported and audit:
            cases.append((r, reported, audit))
    candidates = []
    for request, reported, audit in cases:
        for event in events:
            when = main.parse_time(event.get("event_time", ""))
            if when and when <= audit:
                delta = abs(when - reported)
                if delta <= timedelta(hours=6):
                    candidates.append((delta, request["case_id"], event["activity_id"], request, event))
    # One stable greedy assignment over the entire request cohort, followed by
    # the stricter reciprocal-nearest and six-hour acceptance condition.
    assigned_cases, assigned_events = set(), set()
    greedy = set()
    for delta, cid, aid, request, event in sorted(candidates, key=lambda x: (x[0], x[1], x[2])):
        if cid not in assigned_cases and aid not in assigned_events:
            assigned_cases.add(cid)
            assigned_events.add(aid)
            greedy.add((cid, aid))
    case_nearest = {}
    event_nearest = {}
    for delta, cid, aid, request, event in candidates:
        key = (delta, aid)
        if cid not in case_nearest or key < case_nearest[cid][0]:
            case_nearest[cid] = (key, aid)
        key = (delta, cid)
        if aid not in event_nearest or key < event_nearest[aid][0]:
            event_nearest[aid] = (key, cid)
    accepted = {}
    by_id = {r["case_id"]: r for r in requests}
    event_by_id = {e["activity_id"]: e for e in events}
    for cid, (_, aid) in case_nearest.items():
        if ((cid, aid) in greedy and aid in event_nearest and
                event_nearest[aid][1] == cid):
            event = event_by_id[aid]
            accepted.setdefault(cid, set()).add((event["target_system"], event["resource_id"]))
    return accepted


def show_metric(label: str, predictions: list[dict], truth: dict) -> dict:
    result = evaluate.score(predictions, truth, print_diffs=False)
    evaluate.show_scores(label, result)
    return result


def changed_steps(before: list[dict], after: list[dict], cases: set[str] | None = None) -> None:
    bmap, amap = ({r["case_id"]: r for r in rows} for rows in (before, after))
    for cid in sorted(amap):
        if cases and cid not in cases:
            continue
        old = Counter(map(evaluate.step_id, bmap[cid]["steps"]))
        new = Counter(map(evaluate.step_id, amap[cid]["steps"]))
        add, remove = list((new - old).elements()), list((old - new).elements())
        if add or remove:
            print("  STEP_DIFF", cid, "added=", add, "removed=", remove)


def run() -> None:
    context = main.load_context(rebuild_observations=False)
    sample_context = dict(context)
    sample_context["requests"] = main.read_csv(main.DATA / "sample_deletion_requests.csv")

    # Build all prediction variants before loading public answers.
    baseline, _ = main.predict_all(sample_context, "confirmed")
    assignments = global_mutual_matches(sample_context["requests"], context["activities"])
    original_activity = main.get_activity_candidates
    def with_global_assignment(req, activities, audit, values, users, rows, mode):
        return original_activity(req, activities, audit, values, users, rows, mode) | assignments.get(req["case_id"], set())
    main.get_activity_candidates = with_global_assignment
    account_variant, _ = main.predict_all(sample_context, "confirmed")
    main.get_activity_candidates = original_activity

    original_current = main.current_resource
    def direct_first(pair, rows_by_pair, audit, ctx):
        direct = main.select_latest_observation(rows_by_pair.get(pair, []), audit, ctx["manifest"])
        if direct and direct.get("normalized_state") != "ABSENT":
            try:
                payload = json.loads(direct.get("identifiers", "{}"))
            except (TypeError, json.JSONDecodeError):
                payload = {}
            objects = list(main.nested_payloads(payload))
            status_codes = [obj[k] for obj in objects for k in obj if str(k).casefold() == "status_code"]
            row_counts = [obj[k] for obj in objects for k in obj if str(k).casefold() == "rows"]
            positive = ((status_codes and any(str(v).strip() == "200" for v in status_codes)) or
                        (row_counts and any(str(v).strip().isdigit() and int(str(v).strip()) > 0 for v in row_counts)) or
                        (not status_codes and not row_counts and direct.get("normalized_state") in
                         {"PRESENT", "IDENTIFIABLE", "REDACTED", "ANONYMIZED", "ACTIVE", "BLOCKED", "DISABLED"}))
            scopes = [x for x in [main.sql_scope_state(pair, audit, ctx),
                                  main.json_scope_state(pair, audit, ctx["observations"], ctx["manifest"])] if x]
            latest_scope_capture = max((main.evidence_capture(s[1], ctx["manifest"]) for s in scopes
                                        if main.evidence_capture(s[1], ctx["manifest"])), default=None)
            direct_capture = main.evidence_capture(direct["evidence_id"], ctx["manifest"])
            if positive and direct_capture and latest_scope_capture and latest_scope_capture > direct_capture:
                return {**direct, "scope": False}
        return original_current(pair, rows_by_pair, audit, ctx)
    main.current_resource = direct_first
    direct_variant, _ = main.predict_all(sample_context, "confirmed")
    main.current_resource = original_current

    full_assignments = global_mutual_matches(context["requests"], context["activities"])
    truth = evaluate.load_truth()
    base_score = show_metric("Baseline", baseline, truth)
    account_score = show_metric("Baseline + global mutual account assignment", account_variant, truth)

    # Account-class discovery metrics are unique per case/resource pair.
    expected = {(cid, (s["system_id"], s["resource_id"])) for cid, ans in truth.items()
                for s in ans["steps"] if s["system_id"] == "account_service"}
    proposed = {(cid, pair) for cid, pairs in assignments.items() for pair in pairs}
    tp = len(expected & proposed)
    print("ACCOUNT CLASS GLOBAL MATCH: precision={:.4f} recall={:.4f} TP/predicted/expected={}/{}/{}".format(
        tp / len(proposed) if proposed else 1, tp / len(expected) if expected else 1,
        tp, len(proposed), len(expected)))
    print("ACCOUNT ASSIGNMENT SAMPLE PAIRS:", {k: sorted(v) for k, v in sorted(assignments.items())})
    print("ACCOUNT ASSIGNMENT STEP CHANGES:")
    changed_steps(baseline, account_variant)

    direct_score = show_metric("Baseline + direct observation precedence", direct_variant, truth)
    print("DIRECT PRECEDENCE STEP CHANGES:")
    changed_steps(baseline, direct_variant)
    print("DIRECT PRECEDENCE CASE_01/CASE_24:")
    changed_steps(baseline, direct_variant, {"case_01", "case_24"})

    print("KEEP_CHECK account_assignment=", account_score["step_recall"] > base_score["step_recall"] and account_score["step_precision"] >= base_score["step_precision"],
          "direct_precedence=", direct_score["step_recall"] > base_score["step_recall"] and direct_score["step_precision"] >= base_score["step_precision"])
    print("FULL_COHORT_GLOBAL_ACCOUNT_ASSIGNMENTS", sum(map(len, full_assignments.values())), "cases", len(full_assignments))


if __name__ == "__main__":
    run()
