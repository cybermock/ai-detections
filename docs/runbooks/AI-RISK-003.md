# AI-RISK-003 - Data Collection To AI Upload Kill Chain

> **Detection ID:** AI-RISK-003  
> **Status:** Active  
> **Type:** Correlation notable (high)  
> **Data Source:** `risk` index  
> **Schedule:** `*/15 * * * *`  
> **Lookback:** `kill_chain_window_hours` from `ai_detection_config.csv` (default 4h)

## Overview

This correlation rule identifies a multi-phase behavior chain where a user accumulates risk events that indicate collection/staging behavior followed by AI upload or exfiltration behavior in a short window. It is designed to reduce false positives from isolated events and prioritize suspicious sequences that look like data preparation plus outbound AI usage.

## Detection Logic

1. Query user risk events from `index=risk` for the configured kill-chain time window.
2. Group contributing detections by `ai_kill_chain_phase`.
3. Require evidence of earlier phases (for example collection or staging) plus exfiltration-adjacent activity.
4. Generate a high-severity notable for analysts.

## Triage Steps

1. Confirm total risk and contributing detections:
```spl
index=risk earliest=-4h@h latest=now risk_object="$user$" risk_object_type="user"
| stats sum(risk_score) as total_risk values(search_name) as detections values(ai_kill_chain_phase) as phases by risk_object
```
2. Reconstruct event timeline:
```spl
index=risk earliest=-4h@h latest=now risk_object="$user$" risk_object_type="user"
| table _time search_name risk_score ai_kill_chain_phase risk_message
| sort _time
```
3. Prioritize review of highest-risk upstream detections (for example AI-020, AI-043, AI-007).
4. Validate whether uploaded data likely contained sensitive content (DLP, file names, volume spikes).
5. Escalate immediately if privileged identities or sensitive departments are involved.

## Tuning Guidance

- Increase `kill_chain_window_hours` if true-positive chains are spread over longer periods.
- Decrease `kill_chain_window_hours` if unrelated events are over-correlating.
- Tune upstream high-volume detections before lowering this rule's threshold behavior.

## False Positive Patterns

- Power users running legitimate AI workflows without allowlist coverage.
- Burst activity during sanctioned red-team/tabletop exercises.

## Related Detections

- AI-007, AI-020, AI-043, AI-RISK-001, AI-RISK-002
