## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### Scripted AI CLI Invocation

**Description:** Detect scripted AI CLI invocations where interpreter or shell processes launch AI CLIs. Covers all known AI CLI tools. MITRE: T1059.004

**MITRE ATT&CK:** T1059.004

**Data Models:** Endpoint.Processes

### Tuning
- Use `hdsi_ai_scripted_cli_invocation_filter` macro for exclusions
- Use `hdsi_ai_scripted_cli_invocation_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
