"""OCR all participant PNGs with the explicitly supplied Tesseract binary."""
from __future__ import annotations

import csv
import re
from pathlib import Path

from PIL import Image
import pytesseract


ROOT = Path(__file__).resolve().parents[1]
TESSERACT = Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe")
pytesseract.pytesseract.tesseract_cmd = str(TESSERACT)
manifest = list(csv.DictReader((ROOT / "dataset" / "evidence_files.csv").open(encoding="utf-8-sig")))
rows = [r for r in manifest if Path(r["file_path"]).suffix.casefold() == ".png"]
print("tesseract_exists", TESSERACT.is_file(), "png_count", len(rows))
for row in rows:
    path = ROOT / "dataset" / row["file_path"]
    text = pytesseract.image_to_string(Image.open(path), config="--psm 6")
    normalized = re.sub(r"[ \t]+", " ", text).strip()
    print(f"\n{row['file_id']} origin={row['origin']} chars={len(normalized)}")
    print(normalized[:1000].replace("\n", " | "))
