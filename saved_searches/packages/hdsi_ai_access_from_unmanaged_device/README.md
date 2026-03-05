## Architect Notes
---
### AI Access From Unmanaged Device

**Description:** Detect AI service access from endpoints not registered in asset inventory, indicating unmanaged/BYOD device usage. MITRE: T1078.004

**MITRE ATT&CK:** T1078.004

**Data Models:** Web

### Tuning
- Use `hdsi_ai_access_from_unmanaged_device_filter` macro for exclusions
- Use `hdsi_ai_access_from_unmanaged_device_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
