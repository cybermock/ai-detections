# [Detection ID] - [Detection Name]

> **Detection ID:** [AI-XXX]
> **Status:** Active | Deprecated
> **Risk Score:** [user_score + system_score]
> **MITRE ATT&CK:** [Technique ID] - [Technique Name] ([Tactic])
> **Data Model:** [Web | Endpoint.Processes | Network_Traffic | Network_Resolution | Data_Loss_Prevention | risk index]
> **Schedule:** [cron expression] ([plain English description])
> **Lookback Window:** [earliest_time] to [latest_time]
> **Kill Chain Phase:** [Reconnaissance | Delivery | Exploitation | Installation | Actions on Objectives]
> **Last Updated:** YYYY-MM-DD

---

## Overview

[One to three paragraphs describing what this detection identifies and why it matters to the organization. Include the business risk context: what could go wrong if this activity goes undetected? Who is the typical actor (insider, compromised account, automated tool)?]

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique ID | [e.g., T1567] |
| Technique Name | [e.g., Exfiltration Over Web Service] |
| Tactic | [e.g., Exfiltration] |
| Sub-technique | [e.g., T1567.002 if applicable, otherwise N/A] |

---

## Detection Logic

### Plain English

[Step-by-step description of what the search does, written so a Tier 1 analyst can understand the detection without reading SPL. Use numbered steps.]

1. Query [data model] for events matching [criteria].
2. Filter to [specific conditions].
3. Enrich with [lookups/macros].
4. Evaluate [thresholds/conditions].
5. Exclude sanctioned entities via `ai_unsanctioned_filter`.

### Key Fields

| Field | Description | Example Value |
|---|---|---|
| `user` | The user performing the activity | `jsmith@corp.com` |
| `src` | Source IP or hostname | `10.1.2.50` |
| `provider` | AI service provider name | `OpenAI` |
| [additional fields] | [description] | [example] |

### Thresholds

| Parameter | Default Value | Config Lookup Key | Notes |
|---|---|---|---|
| [threshold_name] | [default] | [control_name in ai_detection_config.csv] | [explanation] |

---

## Triage Steps

> **Estimated triage time:** [X] minutes

### Step 1: Validate the alert

```spl
index=risk search_name="AI RBA - [Detection Name]" risk_object="$user$" earliest=-24h
| table _time risk_object risk_score search_name
```

- Confirm the user and source IP are real (not placeholder or unknown).
- Check whether this is a repeat alert or a new occurrence.

### Step 2: Identify the user

```spl
| inputlookup identity_lookup_expanded
| search identity="$user$"
| table identity first_name last_name email managedBy category priority bunit
```

- Determine the user's role, department, and manager.
- Check if the user is in a privileged or sensitive role.

### Step 3: Review the activity context

```spl
[Specific SPL query to pull raw events that triggered this detection]
```

- [What to look for in the results]
- [How to determine scope]

### Step 4: Check for related detections

```spl
index=risk risk_object="$user$" earliest=-24h
| stats sum(risk_score) as total_risk values(search_name) as detections by risk_object
| sort -total_risk
```

- Look for other AI-related detections firing for the same user.
- Check if the user's cumulative risk is approaching threshold (60 medium, 90 high).

### Step 5: Determine sanctioned status

```spl
| inputlookup ai_sanctioned_entities
| search entity="$user$" OR entity="$src$"
| table entity_type entity provider scope expires reason
```

- If the user or system is sanctioned, this may be a tuning issue.
- If not sanctioned, proceed to response actions.

### Step 6: Make a determination

- **True Positive:** The activity is unsanctioned and represents a genuine policy violation or security risk.
- **Benign True Positive:** The activity is real but authorized (add to allowlist).
- **False Positive:** The detection fired incorrectly (investigate tuning).

---

## True Positive Indicators

- [Sign that this is a real threat, e.g., "User is not in an approved AI pilot program"]
- [Another indicator, e.g., "Upload volume is unusually high for this user's role"]
- [Another indicator]

---

## False Positive Scenarios

| Scenario | Likelihood | Mitigation |
|---|---|---|
| [Common false positive scenario] | [High/Medium/Low] | [How to prevent recurrence] |
| [Another scenario] | [likelihood] | [mitigation] |

---

## Response Actions

### If confirmed True Positive

1. **Contain:** [Immediate containment steps, e.g., "Block the user's access to the AI service via proxy policy"]
2. **Notify:** [Who to notify, e.g., "Inform the user's manager and the data governance team"]
3. **Investigate:** [Deeper investigation steps, e.g., "Determine what data was uploaded"]
4. **Remediate:** [Long-term remediation, e.g., "Revoke API keys, enforce DLP policies"]
5. **Document:** Record findings in the case management system.

### If Benign True Positive

1. Add the user/system to `ai_sanctioned_entities.csv` with appropriate scope and expiration.
2. Document the business justification in the `reason` field.
3. Close the notable as "Benign True Positive."

---

## Tuning Guidance

### Reducing false positives

- [Specific guidance for this detection, e.g., "Add approved users to the allowlist"]
- [Threshold adjustments, e.g., "Increase the burst count threshold from 10 to 15"]

### Adjusting thresholds

```spl
[SPL query to analyze current environment baseline and determine appropriate thresholds]
```

### Adding allowlist entries

To allowlist a specific user for a specific provider:
```
entity_type,entity,provider,scope,expires,owner,reason,enabled,allow_key
user,<username>,<provider>,provider,<YYYY-MM-DD>,<your_name>,<justification>,1,<username>|<provider_lowercase>
```

---

## Related Detections

| Detection ID | Name | Relationship |
|---|---|---|
| [AI-XXX] | [Name] | [How they relate, e.g., "Often fires alongside this detection"] |
| [AI-XXX] | [Name] | [Relationship] |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Model | [e.g., Web] |
| Required Fields | [e.g., url_domain, user, src, bytes_out] |
| Sourcetype Examples | [e.g., pan:traffic, bluecoat:proxysg:access:syslog] |
| CIM Compliance | [Fields that must be mapped to CIM] |
| Acceleration | [Whether data model acceleration is required/recommended] |
| Lookups | [Which lookups this detection depends on] |

---

## Revision History

| Date | Author | Change |
|---|---|---|
| YYYY-MM-DD | [author] | Initial creation |
