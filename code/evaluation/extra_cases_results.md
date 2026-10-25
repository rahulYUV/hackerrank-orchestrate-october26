# Synthetic property cases

Generated from `user_identities.csv`, `user_audit_log.csv`, the evidence manifest, and parsed participant evidence.
No expected step arrays were authored; predictions below come from `main.predict_all`.

| Case | Property | Solver status | Assertion |
|---|---|---|---|
| extra_historical_email_01 | Historical email resolves to user_id `user_523` | INCOMPLETE | PASS |
| extra_keep_update_de_02 | German keep-account/update request has no steps | NOT_APPLICABLE | PASS |
| extra_early_audit_03 | Cutoff is before linked evidence captured at 2026-01-29T11:44:59Z (6 linked observations) | COMPLETE | PASS: no cited capture after cutoff |

## Solver-produced steps

### extra_historical_email_01

Status: `INCOMPLETE`

```json
[
  {
    "step_no": 1,
    "phase": "FINDING",
    "system_id": "account_service",
    "resource_id": "account_4974",
    "operation": "REPORT_REMAINING_RECORD",
    "state": "PRESENT",
    "evidence_id": "evidence_49"
  },
  {
    "step_no": 2,
    "phase": "REMEDIATION",
    "system_id": "account_service",
    "resource_id": "account_4974",
    "operation": "DELETE_RECORD",
    "state": "ABSENT",
    "evidence_id": ""
  },
  {
    "step_no": 3,
    "phase": "VERIFICATION",
    "system_id": "account_service",
    "resource_id": "account_4974",
    "operation": "VERIFY_RECORD_ABSENT",
    "state": "ABSENT",
    "evidence_id": ""
  },
  {
    "step_no": 4,
    "phase": "VERIFICATION",
    "system_id": "security_service",
    "resource_id": "audit_record_3803",
    "operation": "VERIFY_RECORD_PRESENT",
    "state": "PRESENT",
    "evidence_id": ""
  }
]
```

### extra_keep_update_de_02

Status: `NOT_APPLICABLE`

```json
[]
```

### extra_early_audit_03

Status: `COMPLETE`

```json
[]
```

## Citation cutoff check

Case `extra_early_audit_03` had 6 linked observation(s) captured after its audit cutoff.
Citations in the solver-produced result: [].
Assertion: every non-empty citation has manifest capture time at or before `audit_at`.
