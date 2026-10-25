"""Report OCR availability, image manifest entries, and extracted PDF text sizes."""
from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import main


ROOT = Path(__file__).resolve().parents[1]
manifest = main.read_csv(ROOT / "dataset" / "evidence_files.csv")
by_id = {r["file_id"]: r for r in manifest}
print("TESSERACT_PATH", shutil.which("tesseract"))
print("PYTESSERACT_INSTALLED", importlib.util.find_spec("pytesseract") is not None)
print("PNG_FILES")
for row in manifest:
    if Path(row["file_path"]).suffix.casefold() == ".png":
        print(" ", row["file_id"], row["origin"], row["file_path"])

context = main.load_context(rebuild_observations=False)
texts: dict[str, set[str]] = {}
for obs in context["observations"]:
    row = by_id.get(obs["evidence_id"])
    if not row or Path(row["file_path"]).suffix.casefold() != ".pdf":
        continue
    try:
        payload = json.loads(obs["identifiers"])
    except (TypeError, json.JSONDecodeError):
        payload = {}
    text = payload.get("pdf_text", payload.get("text", "")) if isinstance(payload, dict) else ""
    if text:
        texts.setdefault(obs["evidence_id"], set()).add(str(text))
print("PDF_TEXT_LENGTHS")
for row in manifest:
    if Path(row["file_path"]).suffix.casefold() == ".pdf":
        combined = "\n".join(sorted(texts.get(row["file_id"], set())))
        print(" ", row["file_id"], "chars=", len(combined), "origin=", row["origin"], "path=", row["file_path"])
