## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### Unsanctioned AI Desktop App Execution

**Description:** Detect unsanctioned use of AI desktop applications including ChatGPT, Claude, Cursor, Windsurf, Pieces, LM Studio, Jan, Continue, Tabnine, Trae, Zed, and Warp. MITRE: T1204.002

**MITRE ATT&CK:** T1204.002

**Data Models:** Endpoint.Processes

### Tuning
- Use `hdsi_ai_unsanctioned_desktop_app_execution_filter` macro for exclusions
- Use `hdsi_ai_unsanctioned_desktop_app_execution_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
