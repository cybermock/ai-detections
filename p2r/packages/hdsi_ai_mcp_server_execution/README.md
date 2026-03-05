## Architect Notes
---
### MCP Server Execution

**Description:** Detect execution of Model Context Protocol (MCP) servers that allow AI tools to access local resources, files, databases, and APIs. MCP servers expand AI tool capabilities beyond chat and can be used for unauthorized data access. MITRE: T1059

**MITRE ATT&CK:** T1059

**Data Models:** Endpoint.Processes

### Tuning
- Use `hdsi_ai_mcp_server_execution_filter` macro for exclusions
- Use `hdsi_ai_mcp_server_execution_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
