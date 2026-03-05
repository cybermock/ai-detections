## Architect Notes
---
### AI-006: AI API Access From Non-Dev Endpoint

**Description:** Detect API calls to AI providers from endpoints not tagged as development assets. Covers all known AI API endpoints. MITRE: T1071.001

**MITRE ATT&CK:** T1071.001

**Data Models:** Web

### Tuning
- Use `hdsi_ai_006_ai_api_access_from_non_dev_endpoint_filter` macro for exclusions
- Use `hdsi_ai_006_ai_api_access_from_non_dev_endpoint_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
