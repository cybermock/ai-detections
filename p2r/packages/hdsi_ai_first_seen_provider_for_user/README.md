## Architect Notes
---
### AI-009: First Seen AI Provider For User

**Description:** Detect first-seen AI provider usage by a user over a 30-day lookback. MITRE: T1071.001

**MITRE ATT&CK:** T1071.001

**Data Models:** Web

### Tuning
- Use `hdsi_ai_009_first_seen_ai_provider_for_user_filter` macro for exclusions
- Use `hdsi_ai_009_first_seen_ai_provider_for_user_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
