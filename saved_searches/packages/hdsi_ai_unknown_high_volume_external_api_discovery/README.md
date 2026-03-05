## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### Unknown High-Volume External API Discovery

**Description:** Detect unknown high-volume external API usage that may indicate unsanctioned AI service access by specific users and systems.

**Data Models:** Web

### Tuning
- Use `hdsi_ai_unknown_high_volume_external_api_discovery_filter` macro for exclusions
- Use `hdsi_ai_unknown_high_volume_external_api_discovery_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
