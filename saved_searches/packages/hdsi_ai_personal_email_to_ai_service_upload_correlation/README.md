## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### Personal Email To AI Service Upload Correlation

**Description:** Detect file uploads to personal email services followed by AI service uploads within a 1-hour window, indicating data staging through personal email. MITRE: T1048.002

**MITRE ATT&CK:** T1048.002

**Data Models:** Web

### Tuning
- Use `hdsi_ai_personal_email_to_ai_service_upload_correlation_filter` macro for exclusions
- Use `hdsi_ai_personal_email_to_ai_service_upload_correlation_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
