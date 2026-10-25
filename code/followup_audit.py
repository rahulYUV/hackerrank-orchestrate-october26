"""Focused, data-driven follow-up diagnostics; sample answers are scoring only."""
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "code"))
import main  # noqa: E402

context = main.load_context(rebuild_observations=False)

# Recall: expected answers are loaded strictly for scoring.
sample_requests = main.read_csv(ROOT / "dataset/sample_deletion_requests.csv")
context["requests"] = sample_requests
predictions, _ = main.predict_all(context, "confirmed")
truth = {}
with (ROOT / "dataset/sample_output.csv").open(encoding="utf-8-sig", newline="") as f:
    for row in csv.DictReader(f):
        truth[row["case_id"]] = json.loads(row["steps_json"])
pred_by_case = {row["case_id"]: row for row in predictions}
missed = []
for case_id, expected in truth.items():
    actual = pred_by_case[case_id]["steps"]
    remaining = Counter(main.step_id(s) for s in expected) if hasattr(main, "step_id") else Counter(
        tuple(s.get(k, "") for k in ("phase", "system_id", "resource_id", "operation", "state")) for s in expected)
    remaining.subtract(Counter(tuple(s.get(k, "") for k in ("phase", "system_id", "resource_id", "operation", "state")) for s in actual))
    missed.extend([key for key, n in remaining.items() for _ in range(max(0, n))])
print("MISSED EXPECTED STEPS BY OPERATION", dict(sorted(Counter(x[3] for x in missed).items())))
print("MISSED EXPECTED STEPS BY SYSTEM_ID", dict(sorted(Counter(x[1] for x in missed).items())))
print("TOTAL MISSED EXPECTED STEPS", len(missed))

# Whole-output step coverage.
output = list(csv.DictReader((ROOT / "output.csv").open(encoding="utf-8-sig", newline="")))
all_steps = [(row, step) for row in output for step in json.loads(row["steps_json"])]
print("FULL OUTPUT ROWS", len(output))
print("FULL OUTPUT STEPS BY OPERATION", dict(sorted(Counter(s["operation"] for _, s in all_steps).items())))
print("FULL OUTPUT STEPS BY SYSTEM_ID", dict(sorted(Counter(s["system_id"] for _, s in all_steps).items())))

categories = ("EMAIL_DELIVERY_LOG", "MARKETING_PROFILE", "SUPPORT_ATTACHMENT", "CACHE_ENTRY",
              "SECONDARY_IDENTIFIER", "LEGAL_HOLD_RECORD", "ACCOUNT_TOMBSTONE", "BACKUP_ARCHIVE")
step_pairs = {(s["system_id"], s["resource_id"]) for _, s in all_steps}
full_context = main.load_context(rebuild_observations=False)
full_requests = full_context["requests"]
print("CATEGORY COVERAGE")
for category in categories:
    examples = [r for r in full_context["observations"] if main.category_for(r["system_id"], r["resource_id"], r["category"]) == category]
    rule = full_context["rules"].get(category, {})
    if not examples:
        terms = {"EMAIL_DELIVERY_LOG": ("email_delivery",), "MARKETING_PROFILE": ("marketing_profile", "marketing_profiles"),
                 "CACHE_ENTRY": ("cache_entry", "cache_entries"), "SECONDARY_IDENTIFIER": ("secondary_identifier", "secondary_identifiers")}[category]
        matches = []
        for manifest_row in full_context["manifest"].values():
            path = ROOT / "dataset" / manifest_row["file_path"]
            if path.suffix.lower() not in {".sql", ".json", ".log", ".txt"}:
                continue
            raw = path.read_text(encoding="utf-8-sig", errors="replace")
            if any(term in raw.casefold() for term in terms):
                term = next(term for term in terms if term in raw.casefold())
                match = re.search(re.escape(term), raw, re.IGNORECASE)
                matches.append((manifest_row["file_id"], manifest_row["file_path"], raw[max(0, match.start()-80):match.end()+120].replace("\n", " ")))
        print(category, "no parsed observation; matching raw evidence snippets=", matches[:3], "rule=", rule)
        continue
    producing = [r for r in examples if (r["system_id"], r["resource_id"]) in step_pairs]
    example = (producing or examples)[0]
    pair = (example["system_id"], example["resource_id"])
    capture = main.evidence_capture(example["evidence_id"], full_context["manifest"])
    identity_case = None
    for req in full_requests:
        audit = main.parse_time(req.get("audit_at", ""))
        if not audit or not capture or capture > audit:
            continue
        user_ids, identity_values = main.resolve_identity(req, full_context["identities"], full_context["audits"])
        if (main.matching_identity_in_payload(example["identifiers"], identity_values)
                or main.user_reference_match(example["identifiers"], set(user_ids.split(";")))):
            identity_case = req["case_id"]
            break
    print(category, "observations=", len(examples), "resource_pairs_with_output_steps=", len({(r["system_id"], r["resource_id"]) for r in producing}),
          "observation=", (example["evidence_id"], *pair, example["normalized_state"]),
          "rule_action=", rule.get("required_action", rule.get("action", "")),
          "direct_identity_case=", identity_case or "none",
          "any_output_step_for_pair=", pair in step_pairs,
          "payload_keys=", sorted(json.loads(example["identifiers"]).keys()))
