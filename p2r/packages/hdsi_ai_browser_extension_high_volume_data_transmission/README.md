## Architect Notes
---
### AI-024: Browser Extension High-Volume Data Transmission

**Description:** Detect AI browser extensions transmitting high volumes of data, indicating potential bulk page content exfiltration. MITRE: T1176

**MITRE ATT&CK:** T1176

**Data Models:** Web

### Tuning
- Use `hdsi_ai_024_browser_extension_high_volume_data_transmission_filter` macro for exclusions
- Use `hdsi_ai_024_browser_extension_high_volume_data_transmission_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
