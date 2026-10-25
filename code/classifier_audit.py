"""Report request-language templates not covered by explicit deletion cues."""
import csv
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "code"))
import main  # noqa: E402

requests = main.read_csv(ROOT / "dataset/deletion_requests.csv")
outputs = {r["case_id"]: r for r in csv.DictReader((ROOT / "output.csv").open(encoding="utf-8-sig"))}


def has_explicit_deletion_cue(text):
    normalized = main.folded_text(text)
    return any(re.search(p, normalized, re.IGNORECASE) or re.search(p, text, re.IGNORECASE)
               for p in main.DELETION_PATTERNS)


def template_key(text):
    value = text.casefold()
    value = re.sub(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "<email>", value, flags=re.I)
    value = re.sub(r"\+?\d[\d ()-]{6,}\d", "<phone>", value)
    value = re.sub(r"\b\d{2,}\b", "<number>", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


unique = sorted({r.get("request_text", "") for r in requests})
groups = defaultdict(list)
for text in unique:
    if not has_explicit_deletion_cue(text):
        groups[template_key(text)].append(text)
print(f"Unique request_text values={len(unique)}; without an explicit deletion cue={sum(map(len, groups.values()))}; generalized templates={len(groups)}")
for number, (key, texts) in enumerate(sorted(groups.items()), 1):
    print(f"TEMPLATE {number} ({len(texts)} exact unique text(s)): {key}")
    for text in texts:
        print("  TEXT:", text)

print("NOT_APPLICABLE CASES:")
for row in requests:
    result = outputs.get(row["case_id"], {})
    if result.get("deletion_status") == "NOT_APPLICABLE":
        print(row["case_id"], "|", main.classify_request(row.get("request_text", ""))[1], "|", row.get("request_text", ""))
