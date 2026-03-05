## Architect Notes
---
### Browser Extension Activity

**Description:** Detect installation or usage of AI browser extensions (ChatGPT, Copilot, Claude, Perplexity) via proxy logs. Browser extensions can intercept page content and exfiltrate to AI services. MITRE: T1176

**MITRE ATT&CK:** T1176

**Data Models:** Web

### Tuning
- Use `hdsi_ai_browser_extension_activity_filter` macro for exclusions
- Use `hdsi_ai_browser_extension_activity_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
