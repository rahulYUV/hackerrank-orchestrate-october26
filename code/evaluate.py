#!/usr/bin/env python3
"""Score code/main.py against the 32 public examples (scoring only)."""
from __future__ import annotations

import csv
import json
import argparse
from collections import Counter
from pathlib import Path

from main import DATA, ROOT, load_context, predict_all, read_csv, write_output


def load_truth() -> dict[str, dict]:
    path = ROOT / "dataset" / "sample_output.csv"
    truth = {}
    with path.open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            truth[row["case_id"]] = {
                "deletion_status": row["deletion_status"],
                "steps": json.loads(row["steps_json"]),
            }
    return truth


def step_id(step: dict) -> tuple:
    return tuple(step.get(k, "") for k in ("phase", "system_id", "resource_id", "operation", "state"))


def score(predictions: list[dict], truth: dict[str, dict], print_diffs: bool = True) -> dict:
    pred = {r["case_id"]: r for r in predictions}
    case_ids = sorted(truth)
    status_ok = sum(pred.get(c, {}).get("deletion_status") == truth[c]["deletion_status"] for c in case_ids)
    tp = fp = fn = 0
    field_correct = field_total = 0
    exact = 0
    case_scores = []
    for cid in case_ids:
        expected = truth[cid]["steps"]
        actual = pred.get(cid, {}).get("steps", [])
        ec, ac = Counter(map(step_id, expected)), Counter(map(step_id, actual))
        matched = sum((ec & ac).values())
        tp += matched
        fp += sum(ac.values()) - matched
        fn += sum(ec.values()) - matched
        # Match step identity multiplicities first; then compare all seven output fields.
        exp_by, act_by = {}, {}
        for s in expected: exp_by.setdefault(step_id(s), []).append(s)
        for s in actual: act_by.setdefault(step_id(s), []).append(s)
        local_correct = local_total = 0
        for key in set(exp_by) | set(act_by):
            es, aas = exp_by.get(key, []), act_by.get(key, [])
            for i in range(max(len(es), len(aas))):
                e = es[i] if i < len(es) else None
                a = aas[i] if i < len(aas) else None
                for field in ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                    local_total += 1
                    if e is not None and a is not None and e.get(field, "") == a.get(field, ""):
                        local_correct += 1
        field_correct += local_correct
        field_total += local_total
        is_exact = expected == actual
        exact += is_exact
        p = matched / sum(ac.values()) if sum(ac.values()) else (1.0 if not sum(ec.values()) else 0.0)
        r = matched / sum(ec.values()) if sum(ec.values()) else (1.0 if not sum(ac.values()) else 0.0)
        case_scores.append((cid, is_exact, p, r, pred.get(cid, {}).get("deletion_status"), truth[cid]["deletion_status"]))
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    result = {"status_accuracy": status_ok / len(case_ids) if case_ids else 1.0,
              "step_precision": precision, "step_recall": recall, "step_f1": f1,
              "field_accuracy": field_correct / field_total if field_total else 1.0,
              "exact_sequence_rate": exact / len(case_ids) if case_ids else 1.0,
              "tp": tp, "fp": fp, "fn": fn, "pred": pred}
    if print_diffs:
        # Rank by status disagreement, then lower per-case identity F1, then non-exact.
        ranked = []
        for cid, is_exact, _, _, ps, ts in case_scores:
            e, a = truth[cid]["steps"], pred.get(cid, {}).get("steps", [])
            ec, ac = Counter(map(step_id, e)), Counter(map(step_id, a))
            mt = sum((ec & ac).values())
            cp = mt / sum(ac.values()) if sum(ac.values()) else (1.0 if not sum(ec.values()) else 0.0)
            cr = mt / sum(ec.values()) if sum(ec.values()) else (1.0 if not sum(ac.values()) else 0.0)
            cf = 2 * cp * cr / (cp + cr) if cp + cr else 0
            ranked.append((ps != ts, cf, not is_exact, cid))
        print("Five worst case diffs:")
        for _, _, _, cid in sorted(ranked, key=lambda x: (-x[0], x[1], -x[2], x[3]))[:5]:
            print(f"\n{cid}: status expected={truth[cid]['deletion_status']} predicted={pred.get(cid,{}).get('deletion_status')}")
            print(" expected:", json.dumps(truth[cid]["steps"], ensure_ascii=False, separators=(",", ":")))
            print(" predicted:", json.dumps(pred.get(cid, {}).get("steps", []), ensure_ascii=False, separators=(",", ":")))
        print("\nRemaining mismatch patterns by cause:")
        status_causes = Counter()
        missing = Counter()
        extra = Counter()
        citation = Counter()
        for cid in case_ids:
            e, a = truth[cid]["steps"], pred.get(cid, {}).get("steps", [])
            ps = pred.get(cid, {}).get("deletion_status")
            ts = truth[cid]["deletion_status"]
            if ps != ts:
                status_causes[f"status expected {ts}, predicted {ps}"] += 1
            ec, ac = Counter(map(step_id, e)), Counter(map(step_id, a))
            for key, count in (ec - ac).items():
                missing[(key[0], key[1], key[3], key[4])] += count
            for key, count in (ac - ec).items():
                extra[(key[0], key[1], key[3], key[4])] += count
            exp_by = {}
            act_by = {}
            for step in e: exp_by.setdefault(step_id(step), []).append(step)
            for step in a: act_by.setdefault(step_id(step), []).append(step)
            for key in set(exp_by) & set(act_by):
                for expected_step, actual_step in zip(exp_by[key], act_by[key]):
                    if expected_step.get("evidence_id", "") != actual_step.get("evidence_id", ""):
                        citation[(key[1], key[3], expected_step.get("evidence_id", ""), actual_step.get("evidence_id", ""))] += 1
        print(" Status:", dict(status_causes) or "none")
        print(" Missing expected step types (phase, system, operation, state):", dict(missing) or "none")
        print(" Extra predicted step types (phase, system, operation, state):", dict(extra) or "none")
        print(" Evidence citation differences (resource, operation, expected, predicted):", dict(citation) or "none")
    return result


def show_scores(label: str, result: dict) -> None:
    print(f"{label}: status accuracy={result['status_accuracy']:.4f}; step P/R/F1="
          f"{result['step_precision']:.4f}/{result['step_recall']:.4f}/{result['step_f1']:.4f}; "
          f"field accuracy={result['field_accuracy']:.4f}; exact sequence={result['exact_sequence_rate']:.4f}; "
          f"TP/FP/FN={result['tp']}/{result['fp']}/{result['fn']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples-only", action="store_true",
                        help="score the 32 public cases without generating all 518 predictions")
    args = parser.parse_args()
    # Candidate predictions never read sample_output.csv. The scoring file is
    # loaded only after sample predictions have been generated.
    context = load_context(rebuild_observations=not args.samples_only, print_counts=not args.samples_only,
                           requests_path=DATA / "sample_deletion_requests.csv" if args.samples_only else None)
    if not args.samples_only:
        full_context = dict(context)
        full_context["requests"] = read_csv(DATA / "deletion_requests.csv")
        full_confirmed, full_uncertain = predict_all(full_context, "confirmed")
        write_output(full_confirmed)
        print(f"Wrote {len(full_confirmed)} full-dataset predictions; uncertain request texts={len(full_uncertain)}")
        context["requests"] = read_csv(DATA / "sample_deletion_requests.csv")
    confirmed, uncertain = predict_all(context, "confirmed")
    raw, _ = predict_all(context, "raw")
    truth = load_truth()  # scoring input only, deliberately after predictions are generated
    confirm_score = score(confirmed, truth, print_diffs=False)
    raw_score = score(raw, truth, print_diffs=False)
    show_scores("Activity mode confirmed", confirm_score)
    show_scores("Activity mode raw", raw_score)
    chosen, chosen_score = (confirmed, confirm_score) if confirm_score["step_f1"] >= raw_score["step_f1"] else (raw, raw_score)
    if chosen is raw:
        print("Raw activity mode scored higher on samples; output.csv remains the full-dataset confirmed run.")
    print("Final scoring against sample_output.csv:")
    show_scores("Final", chosen_score)
    score(chosen, truth, print_diffs=True)
    # Classifier uncertainty should be reviewed without exposing unnecessary identities.
    print(f"Uncertain sample request classifications: {len(uncertain)}; full-run list is code/uncertain_requests.csv")


if __name__ == "__main__":
    main()
