## Architect Notes
---
### AI-014: Local LLM Listening Port Detected

**Description:** Detect network connections to well-known local LLM service ports (Ollama 11434, LM Studio 1234/43411, Jan 1337, GPT4All 4891, LocalAI/llama.cpp 8080). Indicates an active local LLM server. MITRE: T1219

**MITRE ATT&CK:** T1219

**Data Models:** Network_Traffic

### Tuning
- Use `hdsi_ai_014_local_llm_listening_port_detected_filter` macro for exclusions
- Use `hdsi_ai_014_local_llm_listening_port_detected_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
