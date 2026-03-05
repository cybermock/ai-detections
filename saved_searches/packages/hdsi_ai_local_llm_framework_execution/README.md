## Architect Notes
---
### Local LLM Framework Execution

**Description:** Detect execution of local LLM tooling including ollama, llama.cpp, lmstudio, llamafile, jan, gpt4all, koboldcpp, localai, vllm, mlx, open-webui, and text-generation-launcher. MITRE: T1204.002

**MITRE ATT&CK:** T1204.002

**Data Models:** Endpoint.Processes

### Tuning
- Use `hdsi_ai_local_llm_framework_execution_filter` macro for exclusions
- Use `hdsi_ai_local_llm_framework_execution_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
