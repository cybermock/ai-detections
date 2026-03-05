## Architect Notes
---
### AI-031: AI-Generated Phishing Indicators

**Description:** Detect indicators of AI-generated phishing content including high-volume email composition with AI service correlation. MITRE: T1566.001

**MITRE ATT&CK:** T1566.001

**Data Models:** Web, Email

### Tuning
- Use `hdsi_ai_031_ai_generated_phishing_indicators_filter` macro for exclusions
- Use `hdsi_ai_031_ai_generated_phishing_indicators_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
