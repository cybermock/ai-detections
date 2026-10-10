# [Runbook ID] - HDSI AI [Title]

> **Detection ID:** [AI-0xx runbook ID] (package `[hdsi_ai_<name>]`, `detection_id=[hdsi_ai_<name>]`)
> **Package:** `[hdsi_ai_<name>]` v1.1.0 (deployment type: [global | adhoc])
> **Search name:** `[<Domain> - HDSI AI <Title> - Rule]`
> **Status:** Active. Risk-only (`action.notable = 0`). Notables come from the HDSI RBA AI aggregators.
> **Risk:** [`user` and/or `src`/`dest` (system)]. [Static, or dynamic `risk_score = min(<cap>, round(<base> x ... x risk_multiplier))`]. Literal `_risk` fallback [user N, system N].
> **MITRE ATT&CK:** [Technique ID - Technique Name (Tactic)], matching `action.correlationsearch.annotations`
> **Data Model:** [Web | Network_Resolution | Network_Traffic | Endpoint.Processes | Email.All_Email | DLP.DLP_Incidents | Authentication]
> **Schedule:** `[cron]` ([plain English])
> **Lookback Window:** `[dispatch.earliest_time]` to `[dispatch.latest_time]`
> **Suppression:** [period] per `[alert.suppress.fields]`
> **Kill Chain Phase:** `[recon | initial_access | execution | staging | collection | exfiltration | lateral_movement]` (multi-vector aggregator vector: `[vector]`)
> **Last Updated:** YYYY-MM-DD

<!-- Copy every value above from the package: package.yml (version, deployment_type) and confs/savedsearches.conf
     (stanza, action.risk.param._risk, annotations, cron_schedule, dispatch.*, alert.suppress.*). For an aggregator,
     replace "Search name" with "Correlation search", set Status to "action.notable = 1, action.risk = 0" and give the
     notable severity and rule_title instead of the risk line. For an adhoc package, open with a one-line
     "AD HOC PACKAGE" note that states the exact data requirement. -->

---

## Overview

[One to three paragraphs: what the rule finds, why it matters, the typical actor, and what it emits. State that it writes risk only and that an HDSI RBA AI aggregator decides when the risk becomes a notable.]

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique ID | [e.g. T1567] |
| Technique Name | [e.g. Exfiltration Over Web Service] |
| Tactic | [e.g. Exfiltration] |
| Sub-technique | [e.g. T1567.002, or N/A] |

---

## Detection Logic

### Plain English

[Numbered steps a Tier 1 analyst can follow without reading SPL. Name the package macros that carry each threshold.]

1. `tstats` over [data model], scoped by [pre-filter macro] and `hdsi_ai_<name>_filter` (inline).
2. Normalise [fields]; drop placeholder, machine and service accounts.
3. Resolve the provider or tool with [`ai_domains_filter` | `ai_process_filter`].
4. Apply [threshold macros].
5. Remove approved use with `ai_unsanctioned_filter(<user>,<system>,provider)`.
6. Scale with `ai_risk_multiplier` and set `risk_score`.

### Key Fields

| Field | Description | Example Value |
|---|---|---|
| `user` | The user risk object | `jdoe@example.com` |
| `src` | The system risk object | `10.20.30.40` |
| `provider` | AI service provider | `OpenAI` |
| `risk_multiplier` / `risk_score` | Identity multiplier and final score | `1.0` / `20` |
| [additional fields] | [description] | [example] |

### Thresholds

| Parameter | Default | Macro | Notes |
|---|---|---|---|
| [threshold] | [shipped value] | `hdsi_ai_<name>_<suffix>` | [evidence from the package README] |

---

## Triage Steps

> **Estimated triage time:** [X] minutes. This rule raises no notable. You normally reach it from an HDSI RBA AI aggregator notable or from a user's risk timeline.

Replace `<user>`, `<src>` and `<provider>` with values from the risk event. Set the time picker to cover the risk event.

### Step 1: Validate the risk event

```spl
| from datamodel:"Risk.All_Risk"
| search source="[<Domain> - HDSI AI <Title> - Rule]" risk_object="<user>"
| table _time risk_object risk_object_type risk_score risk_message
| sort - _time
```

- Confirm the risk object is a real person or host, not a placeholder.
- Check whether this is a repeat of an earlier event or a new occurrence.

### Step 2: Identify the user

```spl
| inputlookup identity_lookup_expanded
| search identity="<user>"
| table identity first last email managedBy bunit category priority watchlist
```

- Find the role, business unit (`bunit`) and manager. ES identities have no `department` field.
- If nothing is returned, try the bare account name (no `DOMAIN\` or `@suffix`).

### Step 3: Review the activity

```spl
[The rule's own evidence query for this user or host. Reuse the package's drilldown SPL from confs/savedsearches.conf.]
```

- [What to look for in the results]
- [How to determine scope]

### Step 4: Check related detections and the user's total

```spl
| from datamodel:"Risk.All_Risk"
| search risk_object="*<user>*" source="* - HDSI *"
| stats count as risk_events sum(risk_score) as total_risk values(source) as detections by risk_object risk_object_type
| sort - total_risk
```

- The user aggregators fire at 60 (medium band, at least 2 detections) and 90 (critical) points in 24 h (`ai_detection_config`).

### Step 5: Check sanctioned status

```spl
| inputlookup ai_sanctioned_entities
| eval k=lower(allow_key)
| where like(k, lower("<user>|%")) OR like(k, lower("<src>|%")) OR like(k, "*|%")
| table entity_type entity provider scope expires owner reason enabled allow_key
```

- An expired (`expires` in the past) or disabled (`enabled=0`) entry does not suppress.

### Step 6: Make a determination

- **True Positive:** [the activity is unsanctioned and a real policy violation or security risk].
- **Benign True Positive:** the activity is real and approved, but the approval is missing from `ai_sanctioned_entities` or a package macro.
- **False Positive:** [the rule fired on something that is not the behaviour it looks for].

---

## True Positive Indicators

- [Sign that this is a real threat]
- [Another indicator]

---

## False Positive Scenarios

| Scenario | Likelihood | Mitigation |
|---|---|---|
| [Common false positive, with the live-test evidence] | [High/Medium/Low] | [Macro or lookup change] |

---

## Response Actions

### If confirmed True Positive

1. **Contain:** [immediate containment]
2. **Notify:** [who to notify]
3. **Investigate:** [deeper investigation]
4. **Remediate:** [long-term remediation]
5. **Document:** record the evidence and the decision in the case.

### If Benign True Positive

1. Add a row to `ai_sanctioned_entities` (common package `hdsi_ai_rba_common`) with the narrowest scope that fits, an `expires` date, an `owner` and a `reason`.
2. Close the parent aggregator notable as Benign True Positive, with a reference to the approval.

---

## Tuning Guidance

### Reducing false positives

- [Package macro or lookup change, with the evidence that motivated it]

### Adjusting thresholds

```spl
[Copy the threshold SPL from the package README "Threshold" section.]
```

### Adding allowlist entries

Lookup `ai_sanctioned_entities` (common package). `allow_key` is lowercase `<entity>|<provider>`, or `<entity>|*` for every provider:

```
entity_type,entity,provider,scope,expires,owner,reason,enabled,allow_key
user,jdoe@example.com,OpenAI,provider,2027-03-31,secops,Approved pilot,1,jdoe@example.com|openai
```

---

## Related Detections

| Detection ID | Search name | Relationship |
|---|---|---|
| [AI-0xx] | `[<Domain> - HDSI AI <Title> - Rule]` | [How they relate] |
| AI-RISK-001 / AI-RISK-002 | `Threat - HDSI RBA AI User Risk Threshold Exceeded - Rule` / `Threat - HDSI RBA AI User Critical Risk Threshold Exceeded - Rule` | User risk totals that include this rule's points |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Model | [e.g. `Web`, accelerated (`summariesonly=t`)] |
| Required Fields | [e.g. `Web.url_domain` and/or `Web.site`, `Web.user`, `Web.src`, `Web.bytes_out`] |
| Sourcetype Examples | [e.g. egress proxy, NGFW URL filtering, SSE/CASB] |
| CIM Compliance | [Fields that must be mapped] |
| Acceleration | [Required / recommended, and the summary range a baseline needs] |
| Lookups | [Common package lookups and ES lookups the rule reads] |
| Macros | Common: [`ai_domains_filter`, ...]. Package: `hdsi_ai_<name>_*` |

### Validation summary (read-only live tests, YYYY-MM-DD, 4 production ES tenants)

| Tenant | Data | Parses (search + drilldowns) | Rows | Notes |
|---|---|---|---|---|
| A | [data present?] | [OK] | [n] | [notes, no customer identifiers] |
| B | | | | |
| C | | | | |
| D | | | | |

---

## Revision History

| Date | Author | Change |
|---|---|---|
| YYYY-MM-DD | [author] | Initial creation |
