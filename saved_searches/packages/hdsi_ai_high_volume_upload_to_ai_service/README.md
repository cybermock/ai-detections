## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### High Volume Upload To AI Service

**Description:** Detect high data upload volume to AI providers with tiered risk scoring: 1MB (low), 5MB (medium), 10MB (high), 50MB (critical). MITRE: T1567.002

**MITRE ATT&CK:** T1567.002

**Data Models:** Web

### Tuning
- Use `hdsi_ai_high_volume_upload_to_ai_service_filter` macro for exclusions
- Use `hdsi_ai_high_volume_upload_to_ai_service_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
