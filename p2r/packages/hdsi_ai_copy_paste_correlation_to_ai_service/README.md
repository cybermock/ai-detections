## Architect Notes
---
### AI-025: Copy-Paste Correlation To AI Service

**Description:** Detect clipboard copy events followed by uploads to AI services within a short time window, indicating data staging via copy-paste. MITRE: T1115

**MITRE ATT&CK:** T1115

**Data Models:** DLP, Web

### Tuning
- Use `hdsi_ai_025_copy_paste_correlation_to_ai_service_filter` macro for exclusions
- Use `hdsi_ai_025_copy_paste_correlation_to_ai_service_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
