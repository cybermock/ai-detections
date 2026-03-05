## Architect Notes
---
### User Critical Risk Threshold Exceeded

**Description:** Create a high notable when user AI risk reaches critical threshold in 24 hours.

### Tuning
- Use `hdsi_rba_ai_user_critical_risk_threshold_exceeded_filter` macro for exclusions
- Use `hdsi_rba_ai_user_critical_risk_threshold_exceeded_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
