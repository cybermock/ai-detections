## Architect Notes
---
### Usage Volume Anomaly

**Description:** Statistical anomaly detection using z-score analysis against per-user baseline. Flags users whose daily AI request count exceeds configured standard deviations from historical mean. MITRE: T1567.002

**MITRE ATT&CK:** T1567.002

**Data Models:** Web

### Tuning
- Use `hdsi_ai_usage_volume_anomaly_filter` macro for exclusions
- Use `hdsi_ai_usage_volume_anomaly_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
