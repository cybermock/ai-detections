## Architect Notes
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

---
### AI RBA Common Macros and Lookups

This package contains shared macros used by all AI RBA detection packages.

### Macros
- `ai_domains_filter` - Resolves AI provider domains via ai_provider_domains.csv lookup
- `ai_unsanctioned_filter(3)` - Filters out sanctioned users/systems/groups via ai_sanctioned_entities.csv
- `ai_process_filter` - Resolves AI process names via ai_tool_processes.csv lookup
- `ai_risk_multiplier` - Applies department sensitivity and privilege multipliers to risk scores
- `ai_prompt_injection_patterns_enabled` - Loads enabled prompt injection patterns
- `ai_api_key_patterns_enabled` - Loads enabled API key regex patterns
- `ai_risk_defaults(1)` - Retrieves configurable thresholds from ai_detection_config.csv

### Required Lookups
These CSV lookups must be deployed alongside this package:
- `ai_provider_domains.csv` - AI provider domain registry
- `ai_sanctioned_entities.csv` - Sanctioned user/system/group allowlist
- `ai_tool_processes.csv` - AI CLI/desktop process inventory
- `ai_detection_config.csv` - Configurable thresholds and settings
- `ai_department_sensitivity.csv` - Department risk multipliers
- `ai_deepfake_tools.csv` - Deepfake tool process names
- `ai_prompt_injection_patterns.csv` - Prompt injection regex patterns
- `ai_api_key_patterns.csv` - API key regex patterns
