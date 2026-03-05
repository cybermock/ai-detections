# AI-RISK-004 - Privilege Escalation Plus AI Usage Correlation

> **Detection ID:** AI-RISK-004  
> **Status:** Active  
> **Type:** Correlation notable (high)  
> **Data Source:** `risk` index  
> **Schedule:** `*/15 * * * *`  
> **Lookback:** `-4h@h` to `now`

## Overview

This rule raises a high-severity notable when AI-related risk activity is observed in combination with privilege-escalation or privileged-account signals. The correlation highlights scenarios where AI tooling may be used during or after privileged operations, increasing potential blast radius and abuse impact.

## Detection Logic

1. Search recent user risk events in `index=risk`.
2. Identify privileged/critical identity context and privilege-related detections.
3. Require concurrent AI usage detections in the same user context.
4. Emit a high-severity notable with contributing detections.

## Triage Steps

1. Validate the identity context:
```spl
| inputlookup identity_lookup_expanded
| search identity="$user$"
| table identity category priority department managedBy
```
2. Review correlated risk events:
```spl
index=risk earliest=-4h@h latest=now risk_object="$user$" risk_object_type="user"
| table _time search_name risk_score ai_kill_chain_phase risk_message
| sort _time
```
3. Determine if privileged behavior was expected (change window, break-glass, maintenance job).
4. Confirm host lineage and source endpoints for suspicious pivots.
5. Escalate to incident response if privilege action appears unauthorized or paired with exfil-like AI usage.

## Tuning Guidance

- Keep privileged identity data (`identity_lookup_expanded`) accurate and current.
- Use allowlisting narrowly for approved privileged AI workflows, with expiration dates.
- If noisy, tune upstream privileged usage detections first rather than suppressing this correlation broadly.

## False Positive Patterns

- Legitimate emergency administration with approved AI assistant usage.
- Security engineering testing with temporary privileged accounts.

## Related Detections

- AI-016, AI-026, AI-035, AI-RISK-001, AI-RISK-002
