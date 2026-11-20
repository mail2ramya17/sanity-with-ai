# Compliance evidence pack

Collected 2026-11-20T01:32:22+00:00 · 2/6 controls passing

| | Control | SOC 2 | ISO 27001 | NIST CSF | Evidence (sha256) | Exceptions |
|---|---|---|---|---|---|---|
| ✅ | MFA enforced for all privileged accounts | CC6.1 | A.8.5 | PR.AA-03 | `entra_conditional_access.json` `3e153f00d219` |  |
| ❌ | No storage account allows public blob access | CC6.6 | A.8.20 | PR.DS-01 | `storage_accounts.json` `1fcae22a7592` | {"name": "stg-customer-exports", "allowBlobPublicAccess": true} |
| ❌ | Diagnostic logging enabled on every Key Vault | CC7.2 | A.8.15 | DE.CM-09 | `key_vaults.json` `f761f8b693f0` | {"name": "kv-shared", "diagnosticsEnabled": false} |
| ❌ | Access keys rotated within 90 days | CC6.1 | A.5.17 | PR.AA-01 | `access_keys.json` `e15f4c76c506` | {"principal": "svc-deploy", "ageDays": 212} |
| ✅ | EDR sensor healthy on all production servers | CC7.1 | A.8.7 | DE.CM-01 | `edr_devices.json` `628f1551dbe4` |  |
| ❌ | No privileged account dormant for more than 90 days | CC6.2 | A.5.18 | PR.AA-05 | `privileged_accounts.json` `951f25122d0e` | {"name": "old.admin", "lastSignInDays": 120} |

_Evidence files are hashed at collection time so auditors can verify they were not altered._
