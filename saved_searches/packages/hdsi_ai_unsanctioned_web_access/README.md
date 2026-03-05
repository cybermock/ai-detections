## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### Unsanctioned AI Web Access

**Description:** Consolidated detection for unsanctioned web access to any AI provider. Dynamically uses ai_provider_domains.csv lookup. Replaces deprecated legacy unsanctioned AI web access detections. MITRE: T1071.001

**MITRE ATT&CK:** T1071.001

**Data Models:** Web

### Tuning
- Use `hdsi_ai_unsanctioned_web_access_filter` macro for exclusions
- Use `hdsi_ai_unsanctioned_web_access_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
