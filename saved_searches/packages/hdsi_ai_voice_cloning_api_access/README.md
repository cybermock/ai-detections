## Architect Notes
---
### Voice Cloning API Access

**Description:** Detect web and API access to known voice cloning and speech synthesis services. Voice cloning can be used for social engineering, fraud, and deepfake audio attacks. MITRE: T1588.005

**MITRE ATT&CK:** T1588.005

**Data Models:** Web

### Tuning
- Use `hdsi_ai_voice_cloning_api_access_filter` macro for exclusions
- Use `hdsi_ai_voice_cloning_api_access_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
