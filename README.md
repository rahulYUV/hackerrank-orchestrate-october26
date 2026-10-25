# Deterministic deletion-audit agent

See [problem_statement.md](./problem_statement.md).

## What this project does

The solver builds an observation database from the evidence files, resolves
each requester's current and historical identifiers, determines resource state
at `audit_at`, applies `dataset/deletion_rules.csv`, and writes ordered
findings, remediation, and verification steps to the root `output.csv`.

The implementation is deterministic and makes zero model calls. Local image
OCR uses Tesseract when optional OCR dependencies are installed; otherwise
images are skipped. No API keys or network access are required.

## Requirements

- Python 3
- The repository's `dataset/` directory
- Optional image OCR: `pytesseract`, Pillow, and Tesseract 5.4

## Run

Run these commands from the repository root:

```text
python code/parse_evidence.py --output code/observations.sqlite
python code/main.py
python code/evaluate.py
python code/validate_output.py
```

`parse_evidence.py` must run before `main.py`. The solver writes the completed
prediction file to `output.csv`.

## Output and validation

The output has the columns `case_id,deletion_status,steps_json` and contains
one row for each request. `validate_output.py` checks the 518-row output,
sorting, JSON validity, consecutive step numbers, phase and operation order,
evidence IDs, and evidence capture cutoffs.

## Reproducibility

A clean rebuild reproduces `output.csv` byte for byte. The sample evaluator
uses the 32 public cases for scoring; it is not used by the solver to make
predictions.
