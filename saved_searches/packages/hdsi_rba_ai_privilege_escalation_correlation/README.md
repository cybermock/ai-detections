## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### Privilege Escalation Plus AI Usage Correlation

**Description:** Detect privilege escalation events followed by AI service usage, indicating an attacker leveraging elevated access to exfiltrate via AI.

### Tuning
- Use `hdsi_rba_ai_privilege_escalation_correlation_filter` macro for exclusions
- Use `hdsi_rba_ai_privilege_escalation_correlation_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
