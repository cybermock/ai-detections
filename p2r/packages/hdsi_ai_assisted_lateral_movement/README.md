## Architect Notes
---
### AI-Assisted Lateral Movement

**Description:** Detect AI CLI tool execution followed by remote access tool usage within a 15-minute time window, indicating AI-assisted lateral movement. MITRE: T1021

**MITRE ATT&CK:** T1021

**Data Models:** Endpoint.Processes

### Tuning
- Use `hdsi_ai_assisted_lateral_movement_filter` macro for exclusions
- Use `hdsi_ai_assisted_lateral_movement_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
