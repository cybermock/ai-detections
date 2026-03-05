## Architect Notes
---
### AI-044: Gradual Low-And-Slow Data Exfiltration Via AI

**Description:** Detect gradual cumulative data exfiltration to AI services over a 7-day rolling window. Catches slow-drip exfiltration that evades per-session thresholds. MITRE: T1567.002

**MITRE ATT&CK:** T1567.002

**Data Models:** Web

### Tuning
- Use `hdsi_ai_044_gradual_low_and_slow_data_exfiltration_via_ai_filter` macro for exclusions
- Use `hdsi_ai_044_gradual_low_and_slow_data_exfiltration_via_ai_customizations` macro for post-processing

### Dependencies
This search depends on shared AI RBA macros and lookups:
- `ai_domains_filter` - AI provider domain lookup
- `ai_unsanctioned_filter` - Sanctioned entity allowlist
- `ai_process_filter` - AI process lookup
- Various `ai_*.csv` lookup files
