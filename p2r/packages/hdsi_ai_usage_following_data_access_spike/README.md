## Architect Notes
---
### AI Usage Following Data Access Spike

**Description:** Detect correlation between file access spikes and subsequent AI service uploads, indicating data collection followed by AI exfiltration. MITRE: T1567.002

**MITRE ATT&CK:** T1567.002

**Data Models:** Endpoint.Filesystem, Web

### Tuning
- Use `hdsi_ai_usage_following_data_access_spike_filter` macro for exclusions
- Use `hdsi_ai_usage_following_data_access_spike_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
