# Usage report

## Final full-dataset run

The final run processed all 518 requests and produced `output.csv` after the
evidence database was built. The required command sequence was:

```text
python code/parse_evidence.py --output code/observations.sqlite
python code/main.py
python code/evaluate.py
python code/validate_output.py
```

`parse_evidence.py` must run before `main.py`. The validator passed, and a
clean rebuild reproduced `output.csv` byte for byte.

## Model and token usage

The solver is deterministic and makes zero model calls. Image OCR, when
available, is local Tesseract and uses no tokens.

| Item | Result |
| --- | --- |
| Model provider | not applicable |
| Model name | not applicable |
| Model calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0 |

## Cost

No model calls were made, so model token cost was 0. The estimated monetary
cost is $0.00.

| Item | Result |
| --- | --- |
| Estimated total model cost | $0.00 |
| Estimated cost per request | $0.00 |
| Per-model totals | not applicable |
| Overall totals | 0 model calls, 0 tokens |

## Local processing

The solver builds an observation database from participant-facing evidence,
resolves current and historical identifiers, determines resource state at
`audit_at`, applies `dataset/deletion_rules.csv`, and writes ordered output
steps. Optional `pytesseract`, Pillow, and Tesseract support local image OCR;
without those dependencies, images are skipped. No API keys or network access
are required.
