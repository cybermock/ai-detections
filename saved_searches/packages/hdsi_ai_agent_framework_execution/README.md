## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### AI Agent Framework Execution

**Description:** Detect execution of AI autonomous agent frameworks including AutoGPT, CrewAI, LangChain serve, AutoGen, MetaGPT, BabyAGI, SuperAGI, AgentGPT, OpenDevin, SWE-agent, and similar orchestration tools. MITRE: T1059

**MITRE ATT&CK:** T1059

**Data Models:** Endpoint.Processes

### Tuning
- Use `hdsi_ai_agent_framework_execution_filter` macro for exclusions
- Use `hdsi_ai_agent_framework_execution_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
