## Architect Notes
---
### LLM Model File Download

**Description:** Detect downloads of LLM model files (GGUF, GGML, SafeTensors) from HuggingFace, Ollama registry, and other model repositories. Large model downloads indicate local LLM setup. MITRE: T1105

**MITRE ATT&CK:** T1105

**Data Models:** Web

### Tuning
- Use `hdsi_ai_llm_model_file_download_filter` macro for exclusions
- Use `hdsi_ai_llm_model_file_download_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
