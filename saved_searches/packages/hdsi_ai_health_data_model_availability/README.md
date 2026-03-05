## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### Health-DataModel: AI RBA Data Model Availability

**Description:** Hourly verification that required data models (Web, Endpoint.Processes, Network_Traffic, Network_Resolution, Data_Loss_Prevention, Email, Endpoint.Filesystem) contain recent events. Alerts if any model has zero events in the last 2 hours.

### Tuning
- Use `hdsi_ai_health_data_model_availability_filter` macro for exclusions
- Use `hdsi_ai_health_data_model_availability_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
