## Architect Notes
---
### Suspicious Model File Exfiltration From ML Infrastructure

**Description:** Detect upload or transfer of ML model files from ML/data science infrastructure to external AI services. MITRE: T1567.002

**MITRE ATT&CK:** T1567.002

**Data Models:** Web

### Tuning
- Use `hdsi_ai_suspicious_model_file_exfiltration_filter` macro for exclusions
- Use `hdsi_ai_suspicious_model_file_exfiltration_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
