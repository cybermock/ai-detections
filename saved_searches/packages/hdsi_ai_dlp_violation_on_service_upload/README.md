## Architect Notes
---
### DLP Violation On AI Service Upload

**Description:** Correlate DLP policy violations with AI service destinations. Highest-confidence detection: sensitive data was uploaded to an external AI provider. MITRE: T1567.002

**MITRE ATT&CK:** T1567.002

**Data Models:** DLP

### Tuning
- Use `hdsi_ai_dlp_violation_on_service_upload_filter` macro for exclusions
- Use `hdsi_ai_dlp_violation_on_service_upload_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
