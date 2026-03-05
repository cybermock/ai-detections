## Architect Notes
---
### Health-LookupStaleness: AI RBA Lookup Staleness Alert

**Description:** Weekly check for AI RBA lookup files that have not been updated in 90+ days. Sends email alert for stale lookups requiring maintenance.

### Tuning
- Use `hdsi_ai_health_lookup_staleness_alert_filter` macro for exclusions
- Use `hdsi_ai_health_lookup_staleness_alert_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
