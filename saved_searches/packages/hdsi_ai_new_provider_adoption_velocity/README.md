## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### New AI Provider Adoption Velocity

**Description:** Detect users rapidly adopting multiple new AI providers within a short window (default: 3+ new providers in 7 days). MITRE: T1071.001

**MITRE ATT&CK:** T1071.001

**Data Models:** Web

### Tuning
- Use `hdsi_ai_new_provider_adoption_velocity_filter` macro for exclusions
- Use `hdsi_ai_new_provider_adoption_velocity_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
