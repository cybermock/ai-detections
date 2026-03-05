## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### AI Agent Autonomous Action Detection

**Description:** Detect AI agent frameworks spawning child processes indicating autonomous actions such as file operations, git commands, API calls, or system modifications. MITRE: T1059

**MITRE ATT&CK:** T1059

**Data Models:** Endpoint.Processes

### Tuning
- Use `hdsi_ai_agent_autonomous_action_detection_filter` macro for exclusions
- Use `hdsi_ai_agent_autonomous_action_detection_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
