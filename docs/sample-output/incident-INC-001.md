# INC-001: 10 alerts from edr, siem on payroll-db-01 since 03:00 UTC point to malware activity on a host.

**Severity** critical · **Score** 23.4 · **Owner** finance-platform · **Sources** edr, siem · **Alerts** 10

**Why it matters:** payroll-db-01 is crown jewel; can reach crown jewels: kv-finance; corroborated by independent sources

**Blast radius:** payroll-app, kv-finance

> ⚠️ prompt_injection_in_alert_data:override,role_hijack,mode_switch,verdict_steering

## Timeline (UTC)

| Time | Source | Event |
|---|---|---|
| 03:00 | EDR | Malware executed on payroll database server (4× until 03:09) |
| 03:06 | chat:oncall.sec | EDR critical on payroll-db-01, looking now |
| 03:09 | chat:dba.lee | I logged in with the break-glass account, password is [REDACTED_PASSWORD] if you need it |
| 03:11 | SIEM | Beaconing to known C2 infrastructure (6× until 03:57) |
| 03:14 | chat:oncall.sec | Seeing beaconing to 192.0.2.77 every 60s. Requesting host isolation approval |
| 03:21 | chat:ir.lead | Approved. Isolate payroll-db-01, rotate the break-glass credential, page finance-platform |
| 04:02 | chat:oncall.sec | Host isolated. Beaconing stopped. Imaging disk for forensics |

## Response log (from the audit trail)

| Time (UTC) | Actor | Step |
|---|---|---|
| 2026-11-20 01:32 | ai:template | AI suggested isolate_host |
| 2026-11-20 01:32 | human:alice.analyst | APPROVE: confirmed C2 beaconing |
| 2026-11-20 01:32 | executor:sanity-executor | Executed isolate_host (edr:Machine.Isolate), approved by alice.analyst |
| 2026-11-20 01:32 | ai:template | AI suggested isolate_host |

## Recommended actions (need human approval)

- [ ] `isolate_host`

_Drafted by AI from logs, alerts and chat. Secrets and PII redacted. Review before sharing._
