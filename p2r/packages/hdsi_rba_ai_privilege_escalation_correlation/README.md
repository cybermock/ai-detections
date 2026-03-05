## Architect Notes
---
### AI-RISK-004: Privilege Escalation Plus AI Usage Correlation

**Description:** Detect privilege escalation events followed by AI service usage, indicating an attacker leveraging elevated access to exfiltrate via AI.

### Tuning
- Use `hdsi_ai_risk_004_privilege_escalation_plus_ai_usage_correlation_filter` macro for exclusions
- Use `hdsi_ai_risk_004_privilege_escalation_plus_ai_usage_correlation_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
