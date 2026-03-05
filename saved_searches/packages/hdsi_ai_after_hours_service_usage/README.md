## Architect Notes
---
### After Hours AI Service Usage

**Description:** Detect AI service usage outside business hours (configurable, default before 6AM or after 8PM, or on weekends). After-hours usage may indicate data exfiltration or reduced oversight. MITRE: T1567.002

**MITRE ATT&CK:** T1567.002

**Data Models:** Web

### Tuning
- Use `hdsi_ai_after_hours_service_usage_filter` macro for exclusions
- Use `hdsi_ai_after_hours_service_usage_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
