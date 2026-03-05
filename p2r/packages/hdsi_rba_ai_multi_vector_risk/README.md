## Architect Notes
---
### AI-RISK-005: Multi-Vector AI Risk

**Description:** Detect users triggering 3+ distinct AI detection categories within 24 hours, indicating broad and potentially coordinated AI risk behavior.

### Tuning
- Use `hdsi_ai_risk_005_multi_vector_ai_risk_filter` macro for exclusions
- Use `hdsi_ai_risk_005_multi_vector_ai_risk_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
