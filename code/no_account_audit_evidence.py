"""Inspect identity-linked evidence for ten deletion cases with neither step."""
from __future__ import annotations

import csv
import json
import random
from collections import Counter
from pathlib import Path

import main


ROOT = Path(__file__).resolve().parents[1]
context = main.load_context(rebuild_observations=False)
outputs = {r["case_id"]: r for r in csv.DictReader((ROOT / "output.csv").open(encoding="utf-8-sig"))}
requests = {r["case_id"]: r for r in context["requests"]}
eligible = []
for cid, req in requests.items():
    out = outputs[cid]
    if out["deletion_status"] == "NOT_APPLICABLE":
        continue
    systems = {s["system_id"] for s in json.loads(out["steps_json"])}
    if not ({"account_service", "security_service"} & systems):
        eligible.append(cid)
selected = sorted(random.Random(20261025).sample(sorted(eligible), 10),
                  key=lambda x: int(x.split("_")[-1]))
manifest = context["manifest"]

for cid in selected:
    req = requests[cid]
    user_joined, identity_values = main.resolve_identity(req, context["identities"], context["audits"])
    user_ids = set(user_joined.split(";")) - {""}
    all_ids = {v.casefold() for v in identity_values | user_ids if v}
    audit = main.parse_time(req.get("audit_at", ""))
    observations = []
    resource_ids = set()
    for obs in context["observations"]:
        linked = (main.matching_identity_in_payload(obs["identifiers"], identity_values) or
                  main.user_reference_match(obs["identifiers"], user_ids))
        if linked:
            observations.append((obs, "identity"))
            if obs["resource_id"]:
                resource_ids.add(obs["resource_id"].casefold())
    activities = []
    for row in context["activities"]:
        serialized = json.dumps(row, ensure_ascii=False).casefold()
        resource_link = row.get("resource_id", "").casefold() in resource_ids if row.get("resource_id") else False
        identity_link = main.payload_has_identity(serialized, all_ids)
        if identity_link or resource_link:
            activities.append((row, "resource" if resource_link else "identity"))

    print(f"\nCASE {cid} audit_at={req.get('audit_at')} user_ids={sorted(user_ids)}")
    print("IDENTITY_SET", sorted(identity_values))
    print("LINKED_OBSERVATIONS", len(observations))
    by_format = Counter(Path(manifest[o["evidence_id"]]["file_path"]).suffix.lower() for o, _ in observations)
    print("OBSERVATION_FORMATS", dict(by_format))
    for obs, via in observations:
        capture = main.evidence_capture(obs["evidence_id"], manifest)
        print(" OBS", via, "eligible=", bool(capture and audit and capture <= audit),
              "capture=", capture, "evidence=", obs["evidence_id"], "system=", obs["system_id"],
              "resource=", obs["resource_id"], "category=", obs["category"],
              "state=", obs["normalized_state"], "identifiers=", obs["identifiers"])
    print("LINKED_ACTIVITY_ROWS", len(activities))
    for row, via in activities:
        print(" ACT", via, json.dumps(row, ensure_ascii=False, sort_keys=True))
    pdf_obs = [(o, via) for o, via in observations
               if Path(manifest[o["evidence_id"]]["file_path"]).suffix.lower() == ".pdf"]
    print("LINKED_PDF_TEXTS", len(pdf_obs))
    for obs, via in pdf_obs:
        try:
            payload = json.loads(obs["identifiers"])
        except (TypeError, json.JSONDecodeError):
            payload = {}
        print(" PDF", via, obs["evidence_id"], "text=", payload.get("text", obs["identifiers"]))

print("\nSELECTED_CASES", selected)
