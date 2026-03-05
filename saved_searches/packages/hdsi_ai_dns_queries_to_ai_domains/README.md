## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### DNS Queries To AI Domains

**Description:** Detect DNS resolution of AI service domains. Broad coverage of all known AI provider, API, IDE, and model registry domains. MITRE: T1071.004

**MITRE ATT&CK:** T1071.004

**Data Models:** Network_Resolution

### Tuning
- Use `hdsi_ai_dns_queries_to_ai_domains_filter` macro for exclusions
- Use `hdsi_ai_dns_queries_to_ai_domains_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
