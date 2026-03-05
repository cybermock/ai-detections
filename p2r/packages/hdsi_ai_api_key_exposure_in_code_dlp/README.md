## Architect Notes
---
### AI-033: AI API Key Exposure In Code/DLP

**Description:** Detect AI provider API keys exposed in code repositories, DLP alerts, or log entries using regex patterns. MITRE: T1552.001

**MITRE ATT&CK:** T1552.001

### Tuning
- Use `hdsi_ai_033_ai_api_key_exposure_in_code_dlp_filter` macro for exclusions
- Use `hdsi_ai_033_ai_api_key_exposure_in_code_dlp_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
