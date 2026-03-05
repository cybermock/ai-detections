## Architect Notes
---
### AI-041: Time-Of-Day Usage Pattern Anomaly

**Description:** Detect users whose AI usage time-of-day pattern deviates significantly from their historical pattern using per-user hourly histogram analysis. MITRE: T1567.002

**MITRE ATT&CK:** T1567.002

**Data Models:** Web

### Tuning
- Use `hdsi_ai_041_time_of_day_usage_pattern_anomaly_filter` macro for exclusions
- Use `hdsi_ai_041_time_of_day_usage_pattern_anomaly_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
