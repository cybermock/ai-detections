## Architect Notes
---
### AI-RISK-003: Data Collection To AI Upload Kill Chain

**Description:** Multi-phase kill chain detection: data collection (file access, clipboard, DLP) followed by AI service upload within configurable window.

### Tuning
- Use `hdsi_ai_risk_003_data_collection_to_ai_upload_kill_chain_filter` macro for exclusions
- Use `hdsi_ai_risk_003_data_collection_to_ai_upload_kill_chain_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
