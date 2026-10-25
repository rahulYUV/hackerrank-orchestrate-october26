"""Audit whether each participant-facing log dialect has identity/resource joins."""
import csv
import json
import sqlite3
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def dialect(path):
    name = path.name
    if name.startswith("resource_lookup_trace_"):
        return "readback key/value"
    if name.startswith("service_events_"):
        return "service event key/value"
    if name.startswith("structured_service_events_"):
        return "JSON per line"
    if name.startswith("syslog_archive_"):
        return "RFC5424 syslog"
    if name.startswith("application_trace_"):
        return "bracketed application"
    if name.startswith("operations_stream_"):
        return "pipe operations"
    if name.startswith("cloud_runtime_export_"):
        return "legacy requestId/message"
    return "other log format"


files = list(csv.DictReader((ROOT / "dataset/evidence_files.csv").open(encoding="utf-8-sig")))
by_id = {row["file_id"]: ROOT / "dataset" / row["file_path"] for row in files}
stats = defaultdict(lambda: [0, 0, 0])
db = sqlite3.connect(ROOT / "code/observations.sqlite")
for row in files:
    if not row["file_path"].lower().endswith(".log"):
        continue
    path = ROOT / "dataset" / row["file_path"]
    fmt = dialect(path)
    rows = db.execute("SELECT identifiers FROM observations WHERE evidence_id=?", (row["file_id"],)).fetchall()
    merged = sum(bool(json.loads(r[0]).get("trace_identity")) for r in rows)
    stats[fmt][0] += 1
    stats[fmt][1] += len(rows)
    stats[fmt][2] += merged

for fmt, (nfiles, nobs, merged) in sorted(stats.items()):
    print(f"{fmt}: files={nfiles}, resource_observations={nobs}, with_merged_identity={merged}")
    if not merged:
        print("  No usable joined identity on resource observations.")
