## Architect Notes
---
### AI-026: AI Usage From Personal Account / OAuth Mismatch

**Description:** Detect AI service access where the authenticated user identity does not match corporate identity, suggesting personal account usage. MITRE: T1078.004

**MITRE ATT&CK:** T1078.004

**Data Models:** Web

### Tuning
- Use `hdsi_ai_026_ai_usage_from_personal_account_oauth_mismatch_filter` macro for exclusions
- Use `hdsi_ai_026_ai_usage_from_personal_account_oauth_mismatch_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
