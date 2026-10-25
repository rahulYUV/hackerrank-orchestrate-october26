"""Inspect participant-facing SQL snapshot tables for case_24's account."""
import csv
import json
import sqlite3
from pathlib import Path

import main

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "code" / "observations.sqlite"
manifest = {r["file_id"]: r for r in main.read_csv(ROOT / "dataset" / "evidence_files.csv")}
sample = next(r for r in main.read_csv(ROOT / "dataset" / "sample_deletion_requests.csv") if r["case_id"] == "case_24")
context = main.load_context(rebuild_observations=False)
_, identity_values = main.resolve_identity(sample, context["identities"], context["audits"])
identity_values = {v.casefold() for v in identity_values}
con = sqlite3.connect(DB)
snapshots = con.execute("SELECT evidence_id,captured_at,tables,row_counts FROM sql_snapshots ORDER BY captured_at").fetchall()
obs = context["observations"]
found = []
print("Exact account_5334 row matches across SQL snapshots:")
for evidence_id, captured_at, tables_json, counts_json in snapshots:
    tables = json.loads(tables_json)
    counts = json.loads(counts_json)
    for table in tables:
        if not any(x in table.casefold() for x in ("customer", "profile", "account")):
            continue
        table_rows = [o for o in obs if o["evidence_id"] == evidence_id and o["category"] == table]
        exact = [o for o in table_rows if o["resource_id"].casefold() == "account_5334" or
                 "account_5334" in o["identifiers"].casefold()]
        linked = [o for o in table_rows if main.matching_identity_in_payload(o["identifiers"], identity_values)]
        if exact:
            role = "replica" if "replica" in table.casefold() or "failover" in table.casefold() else "primary/other"
            found.append((evidence_id, captured_at, table, role))
            print(f"  {evidence_id} {captured_at} {table} ({role}) rows={counts.get(table)}")
        if evidence_id == "evidence_51":
            role = "replica" if "replica" in table.casefold() or "failover" in table.casefold() else "primary/other"
            print(f"AT AUDIT SNAPSHOT: {evidence_id} {captured_at} {table} ({role}) rows={counts.get(table)} exact_resource_rows={len(exact)} identity_linked_rows={len(linked)}")
if not found:
    print("  none: no SQL snapshot table contains the literal resource ID")
print("SQL snapshot tables containing literal account_5334:", len(found))
print("SQL snapshot tables containing case_24 identity values:")
identity_hits = []
for evidence_id, captured_at, tables_json, counts_json in snapshots:
    tables = json.loads(tables_json)
    for table in tables:
        table_rows = [o for o in obs if o["evidence_id"] == evidence_id and o["category"] == table]
        hits = [o for o in table_rows if main.matching_identity_in_payload(o["identifiers"], identity_values) or
                main.user_reference_match(o["identifiers"], {"user_24"})]
        if hits:
            role = "replica" if "replica" in table.casefold() or "failover" in table.casefold() else "primary/other"
            identity_hits.append((evidence_id, captured_at, table, role, len(hits)))
            print(f"  {evidence_id} {captured_at} {table} ({role}) identity_rows={len(hits)}")
if not identity_hits:
    print("  none")
print("Case_24's at-cutoff JSON scope observation:")
for row in obs:
    if row["evidence_id"] == "evidence_51" and row["system_id"] == "account_service":
        print(f"  {row['evidence_id']} {manifest[row['evidence_id']]['captured_at']} collection={row['category']} state={row['normalized_state']} payload={row['identifiers']}")
