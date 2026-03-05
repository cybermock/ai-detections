## Architect Notes
---
### Unsanctioned AI CLI Execution

**Description:** Detect unsanctioned use of AI CLI tools including codex, claude, gemini, aider, sgpt, llm, tgpt, mods, fabric, aichat, amazon-q, openai, cline, and gh-copilot. MITRE: T1059

**MITRE ATT&CK:** T1059

**Data Models:** Endpoint.Processes

### Tuning
- Use `hdsi_ai_unsanctioned_cli_execution_filter` macro for exclusions
- Use `hdsi_ai_unsanctioned_cli_execution_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
