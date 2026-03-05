## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### Compromised AI Plugin/Extension Installation

**Description:** Detect installation of known-compromised or suspicious AI plugins/extensions via package managers or browser extension stores. MITRE: T1195.002

**MITRE ATT&CK:** T1195.002

**Data Models:** Endpoint.Processes, Web

### Tuning
- Use `hdsi_ai_compromised_plugin_extension_installation_filter` macro for exclusions
- Use `hdsi_ai_compromised_plugin_extension_installation_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
