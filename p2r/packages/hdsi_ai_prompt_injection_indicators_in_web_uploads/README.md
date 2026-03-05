## Architect Notes
---
### AI-030: Prompt Injection Indicators In Web Uploads

**Description:** Detect known prompt injection patterns in web upload content destined for AI services using DLP/proxy content inspection. MITRE: T1190

**MITRE ATT&CK:** T1190

**Data Models:** DLP

### Tuning
- Use `hdsi_ai_030_prompt_injection_indicators_in_web_uploads_filter` macro for exclusions
- Use `hdsi_ai_030_prompt_injection_indicators_in_web_uploads_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
