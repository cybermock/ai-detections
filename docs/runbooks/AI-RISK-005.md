# AI-RISK-005 - Multi-Vector AI Risk

> **Detection ID:** AI-RISK-005  
> **Status:** Active  
> **Type:** Correlation notable (high)  
> **Data Source:** `risk` index  
> **Schedule:** `*/15 * * * *`  
> **Lookback:** `-24h@h` to `now`  
> **Threshold Control:** `multi_vector_categories` (default 3)

## Overview

This correlation rule detects users who trigger AI detections across multiple distinct risk categories in a 24-hour period. It is intended to catch broad suspicious behavior that spans discovery, execution, staging, and exfiltration-like patterns, even when no single category alone is severe enough to drive immediate triage.

## Detection Logic

1. Query AI risk events for each user over 24 hours.
2. Count distinct detection categories represented in those events.
3. Compare against `multi_vector_categories` from `ai_detection_config.csv`.
4. Generate a high-severity notable when threshold is met or exceeded.

## Triage Steps

1. Identify category spread:
```spl
index=risk earliest=-24h@h latest=now risk_object="$user$" risk_object_type="user"
| stats values(search_name) as detections values(ai_kill_chain_phase) as phases sum(risk_score) as total_risk by risk_object
```
2. Build chronological sequence to assess intent:
```spl
index=risk earliest=-24h@h latest=now risk_object="$user$" risk_object_type="user"
| table _time search_name risk_score ai_kill_chain_phase risk_message
| sort _time
```
3. Validate sanctioned status (`ai_sanctioned_entities`) and role context.
4. Investigate highest-confidence detections first (DLP, high-volume upload, privileged usage).
5. Escalate when multi-category pattern aligns with suspicious timing or sensitive assets.

## Tuning Guidance

- Increase `multi_vector_categories` to reduce noisy broad-but-benign usage.
- Decrease threshold if threat model demands aggressive early escalation.
- Revisit category assignments in upstream detections if distribution looks skewed.

## False Positive Patterns

- Approved engineering experimentation across many AI tools without proper allowlist entries.
- Training or hackathon periods that trigger multiple low/medium detections.

## Related Detections

- AI-RISK-001, AI-RISK-002, AI-028, AI-037, AI-043, AI-045, AI-046
