## Architect Notes
---
### Deepfake Tool Execution/Access

**Description:** Detect execution of known deepfake and synthetic media tools on endpoints. MITRE: T1588.005

**MITRE ATT&CK:** T1588.005

**Data Models:** Endpoint.Processes

### Tuning
- Use `hdsi_ai_deepfake_tool_execution_access_filter` macro for exclusions
- Use `hdsi_ai_deepfake_tool_execution_access_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
