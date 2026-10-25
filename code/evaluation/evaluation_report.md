# Evaluation report

## Scope and method

The solver was evaluated with `code/evaluate.py` against the 32 public cases in
`dataset/sample_deletion_requests.csv`. The reference file
`dataset/sample_output.csv` was used only for scoring and was never read for
predictions.

`code/validate_output.py` was also run against the full generated output. It
checks the 518-row shape, sorted case IDs, valid JSON arrays, consecutive step
numbers, phase and operation ordering, known evidence IDs, and the
`audit_at` evidence cutoff.

## Sample-case results

| Metric | Result |
| --- | ---: |
| Case/status accuracy | 100.00% |
| Step precision | 95.91% |
| Step recall | 84.97% |
| Step F1 | 90.11% |
| Field accuracy | 79.07% |
| Exact sequence match | 40.62% |

## Full-run results

The full run produced one row for each of the 518 requests:

- 369 `INCOMPLETE`
- 139 `COMPLETE`
- 10 `NOT_APPLICABLE`
- 2,799 total steps

`validate_output.py` passed. A clean rebuild reproduced `output.csv` byte for
byte.

Across the 508 deletion cases, resource coverage was:

- account step: 255
- audit step: 402
- both account and audit steps: 219
- neither account nor audit step: 70

## Iteration history

The following results record the solver iterations and the changes associated
with each iteration. Status accuracy is shown first, followed by step
precision, step recall, step F1, field accuracy, and exact sequence match.

| Iteration | Status | Precision | Recall | F1 | Field | Exact sequence |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| v0 first solver | 71.88% | 87.76% | 66.84% | 75.88% | 56.87% | 15.62% |
| + account link, legal-hold rule | 71.88% | 91.72% | 68.91% | 78.70% | 60.21% | 21.88% |
| + ignore `*_started` state, stable references allowed in redaction | 84.38% | 97.16% | 70.98% | 82.04% | 65.70% | 21.88% |
| + trace join across log lines | 93.75% | 95.48% | 76.68% | 85.06% | 70.50% | 28.12% |
| + PDF text match, system inferred from resource prefix | 100% | 95.65% | 79.79% | 87.01% | 73.79% | 34.38% |
| + ownership-only links from later evidence | 100% | 95.73% | 81.35% | 87.96% | 75.43% | 34.38% |
| + direct observation beats later empty scope | 100% | 95.78% | 82.38% | 88.58% | 76.71% | 34.38% |
| + audit ownership for incomplete cases | 100% | 95.91% | 84.97% | 90.11% | 79.07% | 40.62% |
| + OCR of PNG screenshots for catalog-linked resources (marketing, audit, tombstone, others) | 100% | 95.91% | 84.97% | 90.11% | 79.07% | 40.62% |

The OCR iteration left the sample scores unchanged. On the hidden set, 6 cases
changed from `COMPLETE` to `INCOMPLETE`, and `case_63` gained a
`marketing_001` deletion.

## Additional participant-created cases

These cases were generated from participant-facing identity, audit, manifest,
and parsed evidence data. No expected step arrays were authored.

### `extra_historical_email_01`

- Property: a historical email resolves to user `user_523`.
- Solver status: `INCOMPLETE`.
- Assertion: PASS.
- The solver reported an account record remaining, planned deletion of that
  record, and included a retained security audit verification.

### `extra_keep_update_de_02`

- Property: a German keep-account/update request does not authorize deletion.
- Solver status: `NOT_APPLICABLE`.
- Assertion: PASS.
- Steps: `[]`.

### `extra_early_audit_03`

- Property: the cutoff precedes linked evidence captured at
  `2026-01-29T11:44:59Z`.
- Solver status: `COMPLETE`.
- Assertion: PASS; no cited evidence has a capture time after the cutoff.
- Steps: `[]`.

## Failures found and improvements made

- Initially, only 54 of 79 text evidence files produced observations. The
  parser was expanded to handle all seven log formats.
- Lookup lines ending in `*_started` were incorrectly treated as present
  records. They now provide identity information only and never establish
  resource state.
- Identity and state sometimes appeared on different log lines. The parser
  and solver now join them using trace or request IDs.
- Redaction checks incorrectly flagged the stable customer reference. The
  implementation now permits the stable reference and checks only direct
  identifiers: name, email, phone, and hash.

## Limitations

Screenshots are OCRed with Tesseract 5.4
(`TESSERACT_CMD`, default `C:\Program Files\Tesseract-OCR\tesseract.exe`);
without Tesseract, images are skipped and the output differs for the cases
that depend on them.

## Reproducibility

The run is deterministic. Rebuilding the observation database and rerunning
the solver reproduced the output byte for byte, and the validator passed.
