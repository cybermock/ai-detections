# AI-RISK-001 - User Risk Threshold Exceeded - Medium

> **Detection ID:** AI-RISK-001
> **Status:** Active
> **Risk Score:** N/A (this detection generates a notable, not risk)
> **Notable Severity:** Medium
> **MITRE ATT&CK:** N/A (aggregate correlation rule)
> **Data Source:** risk index
> **Schedule:** `*/15 * * * *` (every 15 minutes)
> **Lookback Window:** `-24h@h` to `now`
> **Kill Chain Phase:** N/A (aggregation layer)
> **Last Updated:** 2026-02-13

---

## Overview

This aggregate correlation rule generates a **medium-severity notable event** when a user's cumulative AI-related risk score reaches the medium threshold (default: 60 points) within a rolling 24-hour window. It serves as an early warning signal that a user is accumulating enough AI-related risk events to warrant attention, even if no single detection is high-severity on its own.

Common scenarios that trigger the medium threshold (60 points):
- AI-016 (privileged account, 60 pts) fires once.
- AI-008 (scripted CLI, 50 pts) + AI-012 (DNS, 12 pts) = 62 pts.
- Three low-scoring detections: AI-028 (25 pts) + AI-009 (23 pts) + AI-012 (12 pts) = 60 pts.

This detection suppresses on the user field for 4 hours.

---

## MITRE ATT&CK Mapping

Not applicable -- this is an aggregate correlation rule that draws from all individual AI detections, each with their own MITRE mappings.

---

## Detection Logic

### Plain English

1. Search the `risk` index for all AI detection events (`search_name="AI RBA - *"`, `risk_object_type="user"`) in the past 24 hours.
2. Sum the total risk score per user.
3. Load the medium threshold from `ai_detection_config.csv` (default: 60).
4. Filter to users at or above the threshold.
5. Generate a medium-severity notable.

### Thresholds

| Parameter | Default Value | Config Lookup Key |
|---|---|---|
| Medium risk threshold | 60 | `medium_risk_threshold` |
| Suppress period | 4 hours | N/A (savedsearches.conf) |

---

## Triage Steps

> **Estimated triage time:** 10-15 minutes

1. **Review the contributing detections:**
   ```spl
   index=risk risk_object="$user$" search_name="AI RBA - *" risk_object_type="user" earliest=-24h
   | stats sum(risk_score) as total_risk values(search_name) as detections dc(search_name) as unique_detections by risk_object
   ```
2. **Identify the user and determine their role and sensitivity level.**
3. **Triage the highest-scoring contributing detection** using its individual runbook.
4. **Assess the trajectory:** Is risk accumulating rapidly, or was this a one-time cluster?
5. **Determine response level:** Medium notables typically require same-day review, not immediate escalation.

---

## True Positive Indicators

- Multiple distinct detections fired (not a single detection repeating).
- Total risk is well above 60 and approaching the high threshold (90).
- High-severity detections (AI-007, AI-016, AI-020) are among the contributors.
- User has no AI usage approval.

---

## False Positive Scenarios

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Normal AI usage by an unapproved user triggers 2-3 low-risk detections | High | Review and add to allowlist if appropriate |
| Detection overlap inflates risk (single action triggers multiple low-scoring detections) | Medium | Review individual detection scores; consider adjusting overlap scoring |
| New employee triggers multiple first-time detections during onboarding | Medium | Ensure onboarding includes AI allowlist provisioning |

---

## Response Actions

### If confirmed concerning

1. Review all contributing detections.
2. Contact the user's manager for awareness.
3. Remind the user of the AI usage policy.
4. Monitor for continued accumulation over 24-48 hours.

### If benign

1. Add the user to the allowlist to prevent recurrence.
2. Close as "Benign True Positive."

---

## Tuning Guidance

### Adjusting the medium threshold

```spl
index=risk search_name="AI RBA - *" risk_object_type="user" earliest=-30d
| bin _time span=24h
| stats sum(risk_score) as daily_risk by risk_object _time
| stats perc50(daily_risk) as p50 perc90(daily_risk) as p90 perc95(daily_risk) as p95 max(daily_risk) as max
```

Set the medium threshold above the p90 of daily per-user risk scores to filter routine activity.

---

## Related Detections

| Detection ID | Name | Relationship |
|---|---|---|
| AI-RISK-002 | User Risk Threshold Exceeded - High | Higher threshold (90 pts); escalated severity |
| All active AI detections (AI-004 through AI-044) | Individual detections | All non-aggregate AI detections contribute to this rule |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Source | `risk` index |
| Required Fields | `search_name`, `risk_object`, `risk_object_type`, `risk_score` |
| Lookups | `ai_detection_config.csv` |

---

## Revision History

| Date | Author | Change |
|---|---|---|
| 2026-02-13 | Brainstorm SOC | Initial creation |
