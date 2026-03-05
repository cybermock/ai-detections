## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### Repeated Unsanctioned AI Access Burst

**Description:** Detect repeated unsanctioned access bursts to AI providers. MITRE: T1071.001

**MITRE ATT&CK:** T1071.001

**Data Models:** Web

### Tuning
- Use `hdsi_ai_repeated_unsanctioned_access_burst_filter` macro for exclusions
- Use `hdsi_ai_repeated_unsanctioned_access_burst_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
