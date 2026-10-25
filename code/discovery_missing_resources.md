# Expected resources missed by all tested strategies

## case_04: `account_service` / `account_004`
- `dataset/sample_output.csv` — line 5: case_04,COMPLETE,"[{""evidence_id"":""evidence_54"",""operation"":""VERIFY_RECORD_ABSENT"",""phase"":""VERIFICATION"",""resource_id"":""account_004"",""state"":""ABSENT"",""step_no"":1,""system_id"":""account_service""},{""evidence_id"":""evidence_56"",""opera

## case_07: `support_platform` / `support_001`
- `dataset/sample_output.csv` — line 8: case_07,INCOMPLETE,"[{""evidence_id"":""evidence_58"",""operation"":""REPORT_REMAINING_RECORD"",""phase"":""FINDING"",""resource_id"":""support_001"",""state"":""PRESENT"",""step_no"":1,""system_id"":""support_platform""},{""evidence_id"":"""",""operation"":""

## case_09: `security_service` / `audit_record_4902`
- `dataset/evidence/logs/structured_service_events_eu_west_20260918.log` — line 28: 2026-09-16T08:52:59Z {"severity":"DEBUG","logger":"security_service","service":"security_service","instance":"security-5","pod":"security-c548","region":"ap-south-1","trace_id":"tr-9028396","resource_id":"audit_record_4902","event":"audit_record_read_completed
- `dataset/sample_output.csv` — line 10: case_09,INCOMPLETE,"[{""step_no"":1,""phase"":""FINDING"",""system_id"":""backup_service"",""resource_id"":""backup_4978"",""operation"":""REPORT_RESTORE_RISK"",""state"":""ACTIVE"",""evidence_id"":""evidence_93""},{""step_no"":2,""phase"":""REMEDIATION"",""sy

## case_15: `security_service` / `audit_record_1596`
- `dataset/evidence/logs/service_events_ap_south_20260915.log` — line 103: 2026-09-15T11:59:37Z level=DEBUG service=security_service instance=security-3 pod=security-ecfc region=ap-south-1 trace_id=tr-4314388 resource_id=audit_record_1596 event=audit_record_read_completed integrity_check=passed rows=1
- `dataset/sample_output.csv` — line 16: case_15,INCOMPLETE,"[{""step_no"":1,""phase"":""FINDING"",""system_id"":""integration_service"",""resource_id"":""data_flow_9846"",""operation"":""REPORT_ACTIVE_DATA_FLOW"",""state"":""ACTIVE"",""evidence_id"":""evidence_01""},{""step_no"":2,""phase"":""REMEDI

## case_18: `security_service` / `audit_record_6645`
- `dataset/sample_output.csv` — line 19: case_18,INCOMPLETE,"[{""step_no"":1,""phase"":""FINDING"",""system_id"":""search_service"",""resource_id"":""search_4013"",""operation"":""REPORT_REMAINING_RECORD"",""state"":""PRESENT"",""evidence_id"":""evidence_94""},{""step_no"":2,""phase"":""FINDING"",""s

## case_19: `security_service` / `audit_record_6793`
- `dataset/evidence/logs/service_events_ap_south_20260915.log` — line 44: 2026-09-15T11:54:34Z level=DEBUG service=security_service instance=security-6 pod=security-e1a3 region=eu-central-1 trace_id=tr-6935637 resource_id=audit_record_6793 event=audit_record_read_completed integrity_check=passed rows=1
- `dataset/sample_output.csv` — line 20: case_19,INCOMPLETE,"[{""step_no"":1,""phase"":""FINDING"",""system_id"":""search_service"",""resource_id"":""search_6083"",""operation"":""REPORT_REMAINING_RECORD"",""state"":""PRESENT"",""evidence_id"":""evidence_01""},{""step_no"":2,""phase"":""FINDING"",""s

## case_20: `security_service` / `audit_record_5569`
- `dataset/sample_output.csv` — line 21: case_20,INCOMPLETE,"[{""step_no"":1,""phase"":""FINDING"",""system_id"":""search_service"",""resource_id"":""search_4262"",""operation"":""REPORT_REMAINING_RECORD"",""state"":""PRESENT"",""evidence_id"":""evidence_94""},{""step_no"":2,""phase"":""FINDING"",""s

