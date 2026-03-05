## Architect Notes
---
### Multiple AI Services In Single Session

**Description:** Detect users accessing 3+ distinct AI services within a single hour. May indicate prompt shopping or data exfiltration across multiple channels. MITRE: T1567.002

**MITRE ATT&CK:** T1567.002

**Data Models:** Web

### Tuning
- Use `hdsi_ai_multiple_services_in_single_session_filter` macro for exclusions
- Use `hdsi_ai_multiple_services_in_single_session_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
