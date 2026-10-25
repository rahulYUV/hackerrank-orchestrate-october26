#!/usr/bin/env python3
"""Sample-only experiments for account activity neighbors and audit ownership."""
from __future__ import annotations

import json
import re
import sys
from collections import Counter

import evaluate
import main


def aid(value: str) -> int | None:
    match = re.search(r"(\d+)$", value or "")
    return int(match.group(1)) if match else None


def expected_pairs(truth: dict, system: str | None = None) -> dict[str, set[tuple[str, str]]]:
    return {cid: {(s["system_id"], s["resource_id"]) for s in row["steps"]
                  if system is None or s["system_id"] == system}
            for cid, row in truth.items()}


def case_identity(request: dict, context: dict):
    joined, values = main.resolve_identity(request, context["identities"], context["audits"])
    return {x for x in joined.split(";") if x}, values


_anchor_cache: dict[str, set[int]] = {}
_account_events_cache: list[tuple[int, str, object]] | None = None


def identity_confirmed_activity_ids(request: dict, context: dict) -> set[int]:
    cid = request["case_id"]
    if cid in _anchor_cache:
        return _anchor_cache[cid]
    user_ids, values = case_identity(request, context)
    audit_at = main.parse_time(request["audit_at"])
    found_pairs, rows_by_pair = main.identity_candidate_pairs(
        values, user_ids, context["observations"], audit_at, context["manifest"])
    confirmed = set()
    for row in context["activities"]:
        number = aid(row.get("activity_id", ""))
        if number is None:
            continue
        event_at = main.parse_time(row.get("event_time", ""))
        if not event_at or event_at > audit_at:
            continue
        details = row.get("details", "")
        text_link = main.payload_has_identity(details, values) or any(
            re.search(r"(?<![a-z0-9])" + re.escape(uid.casefold()) + r"(?![a-z0-9])",
                      details.casefold()) for uid in user_ids)
        pair = (main.clean(row.get("target_system")), main.clean(row.get("resource_id")))
        observed_link = pair in found_pairs and any(
            main.matching_identity_in_payload(o.get("identifiers", ""), values) or
            main.user_reference_match(o.get("identifiers", ""), user_ids)
            for o in rows_by_pair.get(pair, []))
        if text_link or observed_link:
            confirmed.add(number)
    _anchor_cache[cid] = confirmed
    return confirmed


def anchored_account_pairs(request: dict, context: dict, k: int) -> set[tuple[str, str]]:
    global _account_events_cache
    anchors = identity_confirmed_activity_ids(request, context)
    audit_at = main.parse_time(request["audit_at"])
    result = set()
    if _account_events_cache is None:
        _account_events_cache = []
        for row in context["activities"]:
            if (main.clean(row.get("source_system")).casefold() != "deletion_worker" or
                main.clean(row.get("event_type")).upper() != "DELETE_RECORD" or
                main.clean(row.get("target_system")).casefold() != "account_service" or
                not main.clean(row.get("resource_id")).casefold().startswith("account_")):
                continue
            number = aid(row.get("activity_id", ""))
            if number is not None:
                _account_events_cache.append((number, main.clean(row["resource_id"]),
                                              main.parse_time(row.get("event_time", ""))))
    for number, resource, event_at in _account_events_cache:
        if not event_at or event_at > audit_at:
            continue
        if any(abs(number - anchor) <= k for anchor in anchors):
            result.add(("account_service", resource))
    return result


def account_class_metrics(predictions: list[dict], truth: dict) -> tuple[float, float, int, int, int]:
    expected = expected_pairs(truth, "account_service")
    predicted = {r["case_id"]: {(s["system_id"], s["resource_id"]) for s in r["steps"]
                               if s["system_id"] == "account_service"}
                 for r in predictions}
    tp = fp = fn = 0
    for cid, pairs in expected.items():
        got = predicted.get(cid, set())
        tp += len(pairs & got)
        fp += len(got - pairs)
        fn += len(pairs - got)
    return (tp / (tp + fp) if tp + fp else 1.0,
            tp / (tp + fn) if tp + fn else 1.0, tp, fp, fn)


def resequence(steps: list[dict]) -> list[dict]:
    steps.sort(key=lambda s: (main.PHASE_ORDER[s["phase"]], main.OPERATION_ORDER[s["operation"]],
                              s["system_id"], s["resource_id"]))
    for n, step in enumerate(steps, 1):
        step["step_no"] = n
    return steps


def audit_owner_variant(predictions: list[dict], context: dict) -> tuple[list[dict], dict[str, set[tuple]]]:
    by_case = {r["case_id"]: r for r in predictions}
    requests = {r["case_id"]: r for r in context["requests"]}
    additions: dict[str, set[tuple]] = {}
    for cid, result in by_case.items():
        if result["deletion_status"] != "INCOMPLETE":
            continue
        user_ids, _values = case_identity(requests[cid], context)
        existing = {(s["system_id"], s["resource_id"], s["operation"], s["state"])
                    for s in result["steps"]}
        linked = set()
        for row in context["observations"]:
            system, resource = main.clean(row.get("system_id")), main.clean(row.get("resource_id"))
            if (resource.casefold().startswith("audit_record_") or system.casefold() == "security_service"):
                if resource and main.audit_owner_match(row.get("identifiers", ""), user_ids):
                    linked.add((system or "security_service", resource))
        for system, resource in sorted(linked):
            step_key = (system, resource, "VERIFY_RECORD_PRESENT", "PRESENT")
            if step_key in existing:
                continue
            result["steps"].append(main.output_step("VERIFICATION", system, resource,
                                                    "VERIFY_RECORD_PRESENT", "PRESENT", ""))
            additions.setdefault(cid, set()).add(step_key)
        resequence(result["steps"])
    return predictions, additions


def keyset(prediction: dict) -> Counter:
    return Counter(evaluate.step_id(s) for s in prediction["steps"])


def main_run() -> None:
    context = main.load_context(rebuild_observations=False,
                                requests_path=main.DATA / "sample_deletion_requests.csv")
    truth = evaluate.load_truth()
    baseline, _ = main.predict_all(context, "confirmed", include_late_audit_ownership=False)
    base_score = evaluate.score(baseline, truth, False)
    evaluate.show_scores("Baseline", base_score)
    print("ACCOUNT CLASS BASELINE P/R/T P FP FN", account_class_metrics(baseline, truth))

    original = main.get_activity_candidates
    best_k = None
    best_predictions = None
    for k in (1, 2, 3, 5):
        def wrapped(request, activities, audit_at, identity_values, user_ids, rows_by_pair,
                    mode, _k=k):
            return original(request, activities, audit_at, identity_values, user_ids,
                            rows_by_pair, mode) | anchored_account_pairs(request, context, _k)
        main.get_activity_candidates = wrapped
        variant, _ = main.predict_all(context, "confirmed", include_late_audit_ownership=False)
        class_p, class_r, tp, fp, fn = account_class_metrics(variant, truth)
        score = evaluate.score(variant, truth, False)
        print(f"ANCHOR k={k} account P/R={class_p:.4f}/{class_r:.4f} TP/FP/FN={tp}/{fp}/{fn} "
              f"overall P/R={score['step_precision']:.4f}/{score['step_recall']:.4f}")
        if class_p >= 0.90 and score["step_recall"] > base_score["step_recall"] and \
                score["step_precision"] >= base_score["step_precision"]:
            if best_k is None or score["step_recall"] > best_predictions[1]["step_recall"]:
                best_k, best_predictions = k, (variant, score)
    main.get_activity_candidates = original
    if best_k is None:
        print("ACCOUNT RULE DECISION: no k met account precision >= 0.90 plus overall recall/precision guard")
        chosen = baseline
    else:
        print("ACCOUNT RULE DECISION: accepted k=", best_k)
        chosen = best_predictions[0]
        evaluate.show_scores(f"Accepted account-neighbor k={best_k}", best_predictions[1])

    before_audit = json.loads(json.dumps(chosen))
    after_audit, adds = audit_owner_variant(chosen, context)
    audit_score = evaluate.score(after_audit, truth, False)
    evaluate.show_scores("Audit-owner experiment", audit_score)
    print("AUDIT OWNER ADDED STEPS", {cid: sorted(v) for cid, v in adds.items()})
    print("AUDIT OWNER REMOVED STEPS {}")
    kept = (audit_score["step_recall"] > (best_predictions[1]["step_recall"] if best_k else base_score["step_recall"])
            and audit_score["step_precision"] >= (best_predictions[1]["step_precision"] if best_k else base_score["step_precision"]))
    print("AUDIT OWNER RULE DECISION:", "accepted" if kept else "rejected by recall/precision guard")
    final = after_audit if kept else before_audit
    selected_score = audit_score if kept else (best_predictions[1] if best_k else base_score)
    evaluate.show_scores("Selected sample predictions", selected_score)

    selected_by_case = {r["case_id"]: r for r in final}
    baseline_by_case = {r["case_id"]: r for r in baseline}
    print("NAMED CASE BEFORE/AFTER")
    for cid in ("case_78", "case_188", "case_197", "case_284", "case_293", "case_298", "case_377"):
        print(cid, "before", json.dumps(baseline_by_case.get(cid), ensure_ascii=False, separators=(",", ":")))
        print(cid, "after", json.dumps(selected_by_case.get(cid), ensure_ascii=False, separators=(",", ":")))

    # These brief historical questions are answered from participant evidence
    # and scoring examples; no ground truth is used to form predictions.
    print("AUDIT RESOURCE MULTIPLICITY IN SAMPLE TRUTH")
    sample_requests = {r["case_id"]: r for r in context["requests"]}
    user_audit_counts: dict[str, list[tuple[str, str]]] = {}
    for cid, expected in sorted(truth.items()):
        audits = sorted(s["resource_id"] for s in expected["steps"]
                        if s["system_id"] == "security_service" and s["resource_id"].startswith("audit_record_"))
        user_ids, _ = case_identity(sample_requests[cid], context)
        for uid in user_ids:
            user_audit_counts.setdefault(uid, []).extend((cid, audit) for audit in audits)
        if audits:
            print(cid, "user_id(s)=", sorted(user_ids), "expected_audit_records=", audits)
    repeated = {uid: links for uid, links in user_audit_counts.items() if len(links) > 1}
    print("same user across multiple expected audit steps", repeated or "none in these 32 cases")

    print("MARKETING_001 EXPECTED SAMPLE REFERENCES")
    for cid, expected in sorted(truth.items()):
        refs = [s for s in expected["steps"] if s["resource_id"] == "marketing_001"]
        if refs:
            print(cid, json.dumps(refs, ensure_ascii=False))
    print("MARKETING_001 OBSERVATIONS")
    for o in context["observations"]:
        if "marketing_001" in o["resource_id"].casefold() or "marketing_001" in o["identifiers"].casefold():
            print(o["evidence_id"], o["system_id"], o["resource_id"], o["normalized_state"], o["identifiers"][:1200])

    print("NAMED NON-SAMPLE CASES STRICT BEFORE / AUDIT-OWNER AFTER")
    full_requests = {r["case_id"]: r for r in main.read_csv(main.DATA / "deletion_requests.csv")}
    for cid in ("case_78", "case_188", "case_197", "case_284", "case_293", "case_298", "case_377"):
        request = full_requests.get(cid)
        if not request:
            print(cid, "not found in deletion_requests.csv")
            continue
        before = main.solve_case(request, context, "confirmed", False)[0]
        after = main.solve_case(request, context, "confirmed", True)[0]
        print(cid, "before", json.dumps(before, ensure_ascii=False, separators=(",", ":")))
        print(cid, "after", json.dumps(after, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main_run()
