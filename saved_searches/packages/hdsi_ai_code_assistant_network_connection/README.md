## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### Code Assistant Network Connection

**Description:** Detect IDE and code editor processes making network connections to AI backend services. Correlates application with AI destination. MITRE: T1071.001

**MITRE ATT&CK:** T1071.001

**Data Models:** Network_Traffic

### Tuning
- Use `hdsi_ai_code_assistant_network_connection_filter` macro for exclusions
- Use `hdsi_ai_code_assistant_network_connection_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
