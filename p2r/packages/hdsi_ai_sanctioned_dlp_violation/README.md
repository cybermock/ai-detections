## Architect Notes
---
### AI-038: Sanctioned AI DLP Violation

**Description:** Detect DLP policy violations involving sensitive data uploaded to sanctioned (approved) AI providers. Even approved AI tools should not receive sensitive data like PII, source code, or trade secrets. MITRE: T1567.002

**MITRE ATT&CK:** T1567.002

**Data Models:** DLP

### Tuning
- Use `hdsi_ai_038_sanctioned_ai_dlp_violation_filter` macro for exclusions
- Use `hdsi_ai_038_sanctioned_ai_dlp_violation_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
