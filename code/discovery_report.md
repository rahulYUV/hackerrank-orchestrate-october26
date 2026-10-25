# Sample resource discovery measurement

Ground truth is the unique `(system_id, resource_id)` set across every step in each row of `dataset/sample_output.csv`, including proposed remediation and future verification targets. `A` uses literal case-insensitive substring matching against parsed observation `identifiers`. `B` filters activity rows where `source_system` is `deletion_worker` or `privacy_intake`, scores `(target_system, resource_id)`, and uses before-only or symmetric windows around `reported_at`. Precision is 0 when a strategy finds no pairs. Overall micro scores aggregate pair counts; macro scores average the 32 per-case scores.

`C_union_*` is A union B. `C_union_*_1hop` adds observation pairs whose `customer_reference` or identifier token is shared with an A/B seed resource. The exact per-case precision/recall for every strategy is in `discovery_case_metrics.csv`; resource citation/capture details are in `discovery_resource_audit.csv` and `discovery_citation_summary.csv`.

Identity resolution failures: none.

## Overall precision and recall

| Strategy | Micro precision | Micro recall | Macro precision | Macro recall | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| A_identity | 0.185 | 0.649 | 0.311 | 0.562 | 72 | 317 | 39 |
| B_1h_before | 0.243 | 0.297 | 0.290 | 0.294 | 33 | 103 | 78 |
| C_union_1h_before | 0.176 | 0.811 | 0.300 | 0.758 | 90 | 420 | 21 |
| C_union_1h_before_1hop | 0.164 | 0.811 | 0.273 | 0.758 | 90 | 459 | 21 |
| B_1h_symmetric | 0.279 | 0.505 | 0.447 | 0.562 | 56 | 145 | 55 |
| C_union_1h_symmetric | 0.174 | 0.874 | 0.350 | 0.872 | 97 | 462 | 14 |
| C_union_1h_symmetric_1hop | 0.156 | 0.874 | 0.325 | 0.872 | 97 | 525 | 14 |
| B_6h_before | 0.196 | 0.396 | 0.224 | 0.383 | 44 | 180 | 67 |
| C_union_6h_before | 0.163 | 0.874 | 0.251 | 0.812 | 97 | 497 | 14 |
| C_union_6h_before_1hop | 0.150 | 0.874 | 0.231 | 0.812 | 97 | 548 | 14 |
| B_6h_symmetric | 0.220 | 0.766 | 0.295 | 0.768 | 85 | 301 | 26 |
| C_union_6h_symmetric | 0.144 | 0.937 | 0.235 | 0.927 | 104 | 618 | 7 |
| C_union_6h_symmetric_1hop | 0.134 | 0.937 | 0.224 | 0.927 | 104 | 672 | 7 |
| B_24h_before | 0.133 | 0.396 | 0.169 | 0.383 | 44 | 287 | 67 |
| C_union_24h_before | 0.138 | 0.874 | 0.169 | 0.812 | 97 | 604 | 14 |
| C_union_24h_before_1hop | 0.123 | 0.874 | 0.154 | 0.812 | 97 | 691 | 14 |
| B_24h_symmetric | 0.138 | 0.766 | 0.157 | 0.768 | 85 | 531 | 26 |
| C_union_24h_symmetric | 0.109 | 0.937 | 0.114 | 0.927 | 104 | 848 | 7 |
| C_union_24h_symmetric_1hop | 0.097 | 0.937 | 0.103 | 0.927 | 104 | 966 | 7 |

## Expected resources missed by every strategy

Count: 7. See `discovery_missing_resources.md` for each resource and every literal dataset occurrence.

## Citation freshness counts

Cited expected-resource pairs: 75; latest direct resource capture: 70; cited but not latest: 0; latest direct capture not assessable because the resource ID is absent from searchable evidence content: 5.

## Citation freshness

Resource-level citation freshness compares each cited `evidence_id` with the latest manifest capture at or before `audit_at` among evidence files where that resource ID occurs literally or as a parsed observation. Scope-only evidence for absent resources is reported separately; if no evidence file contains the resource ID, latest resource-capture status is not assessable from direct occurrences. The `cited_support_type` column distinguishes direct resource evidence, parsed empty-snapshot evidence, and citations not textually linked by this scan. PDF text extraction was unavailable in this runtime (neither `pypdf` nor PyMuPDF is installed), and PNGs were not OCR'd. See `discovery_resource_audit.csv` for per-pair file IDs, literal paths, citations, scope sources, and cutoff comparison.
