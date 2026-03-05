## Architect Notes
---
### AI-022: AI Access Via VPN/Proxy Evasion

**Description:** Detect AI service access through known VPN or proxy services, indicating policy bypass attempts. MITRE: T1090.003

**MITRE ATT&CK:** T1090.003

**Data Models:** Web

### Tuning
- Use `hdsi_ai_022_ai_access_via_vpn_proxy_evasion_filter` macro for exclusions
- Use `hdsi_ai_022_ai_access_via_vpn_proxy_evasion_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
