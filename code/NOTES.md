# Phase 1 evidence investigation notes

These notes are limited to the participant-facing `dataset/` files, the public 32-row `sample_output.csv`, and the supplied problem statement. They describe what is directly supported by those sources; sample patterns are not treated as universal rules unless the policy states them.

## How sample cases find resources

- The sample outcomes name concrete `system_id` and `resource_id` pairs. Those pairs can be located in the evidence contents, not from the manifest alone. For example, `case_11`'s resources (search `search_052`, analytics `analytics_2034`, support `support_864`, and data flow `data_flow_9522`) all appear in `customer_account_handover_20261001.txt`, cited as `evidence_03`.
- That handover's lines associate each resource with a system, category, state, and a subject reference such as the request email. Broader resource discovery therefore relies on resolving request emails to current or historical identity fields, then matching those identifiers or stable user references in evidence. The complete solver's matching strategy is **not verified** by this phase.
- Structured JSON evidence nests records under snapshot metadata such as `data_store` and `collection`. The SQL files are SQLite-compatible snapshots with multiple tables, including primary and failover/replica tables; compare table rows and snapshot time rather than relying on a single table.
- A manifest entry supplies the `file_id`, path, and capture time. In output, the `evidence_id` is the manifest's `file_id` (for example, `evidence_03`), not the filename or resource ID.

## Evidence citation patterns

- In incomplete samples, findings cite a file ID that contains the observed state. Samples 11 and 18 cite `evidence_03` and `evidence_94`, respectively, for several records in one consolidated artifact. Samples 5–10 cite evidence IDs for their residual record or restore risk.
- For `COMPLETE` samples, verification steps cite evidence showing compliant state at the relevant cutoff. Cases 3 and 21–28 cite one consolidated evidence item across multiple verification rows; cases 1, 2, and 4 cite evidence items for the account and analytics checks.
- The sample and contract agree that proposed remediation and future verification steps for `INCOMPLETE` cases have `evidence_id: ""`. Evidence after `audit_at` must not be used (problem statement contract); the detailed cutoff-to-manifest matching behavior is not inferred here.

## Policy: DELETE versus REDACT

`dataset/deletion_rules.csv` explicitly distinguishes categories and conditions:

- `USER_PROFILE`, `SECONDARY_IDENTIFIER`, `SEARCH_INDEX_ENTRY`, `CACHE_ENTRY`, `USER_EXPORT`, `MARKETING_PROFILE`, and subject-only `SUPPORT_ATTACHMENT` require `DELETE` under their listed conditions.
- A `SUPPORT_MESSAGE` containing shared customer/agent/order context must be `REDACT`, preserving the shared conversation while removing identifying information. A message that does not meet that condition is **not specified by that row**; do not generalize from it.
- `EMAIL_DELIVERY_LOG` containing a user email is `REDACT`.
- `ACCOUNT_TOMBSTONE` is `REDACT`: preserve its stable internal user reference when needed, but remove direct identifiers. The JSON snapshot shows a compliant example (`tombstone_440`) with null direct identifiers and a noncompliant example (`tombstone_9178`) with identifying fields still populated; sample cases 31 and 32 match those respective verification/finding patterns.

## Analytics: ANONYMIZE versus DELETE

- `ANALYTICS_PROFILE` and `PRODUCT_TELEMETRY` are `ANONYMIZE` when still attributable to a user (`deletion_rules.csv`, rules 7–8). This means retaining the record after breaking its link to the user, not deleting it.
- An analytics record shown as still identifiable is reported as `REPORT_EXPOSED_PII` and remediated with `ANONYMIZE_RECORD` in samples 11, 18–19, 22, and 29–30. A compliant analytics record is verified with `VERIFY_RECORD_ANONYMIZED` in samples 3–4, 21, and 25–28.
- Whether a specific analytics row qualifies as attributable must be established from its evidence and the policy condition; a universal identifier test is **not verified** here.

## Retained audit records

- The policy says `SECURITY_AUDIT_LOG` records within the supplied retention period are `RETAIN` (rule 12). Samples that include an audit resource use `VERIFY_RECORD_PRESENT`; this appears in incomplete samples 9 and 11–20, 22–24, 29–30, 32, and complete samples 3, 21, and 25–28, 31.
- It does not appear in the small early samples 5–8 or 10, which do not include an audit resource in their sample steps. The precise condition that determines whether an audit record is in scope for an individual sample is **not verified**; use participant-visible evidence and the supplied retention rule.

## NOT_APPLICABLE

The problem statement says a case is `NOT_APPLICABLE` when its request text asks for a non-deletion action (examples: access, correction, export, or marketing opt-out) and does not authorize deletion. Its steps array must be empty. This status is determined from request intent, not from the workflow status or whether evidence happens to contain records. The exact language classifier is **not specified** by the sample and is not guessed here.

## Parser scope

`parse_evidence.py` processes `.sql`, `.log`, `.json`, and `.txt` evidence into a SQLite `observations` table and reports file counts, extracted row counts by format, and row counts by normalized state. It handles bracketed service logs, readback key/value logs, legacy requestId/message logs, service/event logs, pipe-delimited operations streams, JSON-per-line structured logs, and syslog-style streams. It intentionally skips `.pdf` and `.png` during this phase. The `identifiers` column stores the source record's visible fields as JSON to retain matching material for later investigation; `evidence_id` is also retained for citations.

The observations table retains the source `state` and adds `normalized_state`. SQL files also populate `sql_snapshots` with each snapshot's capture time and table-name list. This allows a missing resource to be distinguished from a missing table; JSON snapshots with an explicitly empty `records` list produce a scope-level `ABSENT` observation with an empty `resource_id`.

### Parser run and sample support audit

The run parsed 951 JSON, 1,336 log, 891 SQL, and 41 TXT observations (3,219 total). Normalized-state counts were: `ABSENT` 211, `ACTIVE` 162, `ANONYMIZED` 97, `BLOCKED` 46, `DISABLED` 51, `IDENTIFIABLE` 56, `PRESENT` 2,574, and `REDACTED` 22. All 24 SQL files have a `sql_snapshots` row. One supported-format evidence item has no resource observations: `evidence_90`, whose inventory tables are present in `sql_snapshots`; PDFs and PNGs are intentionally skipped.

Sample support found in the parsed observations:

- `case_01`: `evidence_54` contains both account profile tables; `account_001` has no row in the complete snapshot. This is a table-scope absence, not a direct record observation.
- `case_03`: `evidence_94` records `account_7566` with `rows=0` / HTTP 404, `audit_record_2016` as read, and `analytics_9406` with direct identifier fields null.
- `case_05`: `evidence_54` has `account_005` in `customer_profiles_failover_replica`, normalized to `PRESENT`.
- `case_06`: `evidence_57` has `search_001` in `search_documents_primary`, normalized to `PRESENT`.
- `case_11`: `evidence_03` records `search_052` as found, `analytics_2034` and `support_864` as identifiable, and `data_flow_9522` as active.
- `case_31`: `evidence_51` has an empty `customer_profiles` snapshot scope (absence), `audit_record_6909` present, and `tombstone_440` retained with direct identifiers null (redacted).

The incomplete-case remediation and post-remediation verification steps in these samples have empty evidence IDs by contract; they are planned actions and do not claim that the future state is already observed.
