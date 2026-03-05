## Architect Notes
---
### User Peer Group AI Usage Anomaly

**Description:** Detect users whose AI usage significantly deviates from their department peer group using eventstats z-score analysis. MITRE: T1567.002

**MITRE ATT&CK:** T1567.002

**Data Models:** Web

### Tuning
- Use `hdsi_ai_user_peer_group_usage_anomaly_filter` macro for exclusions
- Use `hdsi_ai_user_peer_group_usage_anomaly_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
