## Architect Notes
---
### AI-016: Privileged Account AI Service Usage

**Description:** Detect AI service usage by privileged accounts (admins, service accounts, critical-priority users). Requires identity_lookup_expanded in Splunk ES. MITRE: T1078.004

**MITRE ATT&CK:** T1078.004

**Data Models:** Web

### Tuning
- Use `hdsi_ai_016_privileged_account_ai_service_usage_filter` macro for exclusions
- Use `hdsi_ai_016_privileged_account_ai_service_usage_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
