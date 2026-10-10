# AI-RISK-001 - HDSI RBA AI User Risk Threshold Exceeded (Medium)

> **Detection ID:** AI-RISK-001
> **Package:** `hdsi_rba_ai_user_risk_threshold_exceeded` (v1.1.0, `deployment_type: global`)
> **Correlation search:** `Threat - HDSI RBA AI User Risk Threshold Exceeded - Rule`
> **Status:** Active (ships with `enable_alerting: false`; enable together with AI-RISK-002 as one separately approved change)
> **Type:** Risk aggregator. Creates a notable (`action.notable = 1`), writes **no** risk (`action.risk = 0`)
> **Notable:** severity `medium`, security domain `threat`, title `HDSI AI User Risk Threshold Exceeded - Medium (<user_key>, <total_risk> points)`
> **Risk Score:** N/A. The `_risk` entry (user, 35) is kept for conformance only; nothing is written
> **MITRE ATT&CK:** T1588.007 Obtain Capabilities: Artificial Intelligence (Resource Development). Contributing techniques per notable in `contributing_mitre_attack`
> **Data Source:** ES risk index (`index=risk`, macro `..._risk_index`) and `index=notable` (hand-off guard); drilldowns use the `Risk.All_Risk` data model
> **Schedule:** `0-59/15 * * * *` (every 15 minutes)
> **Lookback Window:** `-24h@m` to `now` (rolling 24 hours)
> **Suppression:** 24 hours (`86400s`) per `user_key`
> **Kill Chain Phase:** N/A (aggregation layer; phases listed per notable)
> **Last Updated:** 2026-10-09

---

## Overview

This is the medium band of the HDSI AI user threshold pair. It raises one medium notable when one person's HDSI AI risk over a rolling 24 hours is:

- at or above `medium_risk_threshold` (default **60**) and below `high_risk_threshold` (default **90**), both from the common `ai_detection_config` lookup, and
- built from at least **two distinct** HDSI AI detections.

Totals at or above 90 belong to AI-RISK-002 (critical). Users who already received an AI-RISK-002 notable in the last 24 hours are skipped, so a total that decays from critical back into the medium band does not alert twice. One total therefore never produces both notables.

The two-detection rule is deliberate: one detection firing repeatedly, or one high-scoring event, does not raise this notable. That risk is still on the user in ES Risk Analysis, and a single detection that reaches 90 still goes to AI-RISK-002.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique ID | T1588.007 (annotation) |
| Technique Name | Obtain Capabilities: Artificial Intelligence |
| Tactic | Resource Development |
| Sub-technique | N/A. Techniques actually observed are in `contributing_mitre_attack` |

---

## Detection Logic

### Plain English

1. Read `index=risk` (macro `..._risk_index`) for `risk_object_type="user"` events whose `source` matches `* - HDSI AI * - Rule` or whose `detection_id` starts with `hdsi_ai_`. Health checks are excluded. `risk_object` must be set and must not be `unknown`, `-` or end in `$`. The tenant filter is applied inline.
2. Build `user_key` (macro `..._user_key`, identical to AI-RISK-002): lower-case `risk_object` with `@domain` and `DOMAIN\` removed; built-in local accounts keep their qualifier (`host/administrator`).
3. Drop accounts matched by `..._excluded_accounts` (identical to AI-RISK-002): placeholders, `$` accounts, OS service identities, `root`/`nobody`/`daemon`, `krbtgt`, bare built-ins.
4. Sum risk per `user_key` and `detection_key` (`detection_id`, or `source` when missing), then per person: `total_risk`, `distinct_detections`, `risk_event_count`, a points breakdown, the top contributor and its share, phases and MITRE.
5. Read `medium_risk_threshold` and `high_risk_threshold` (defaults 60 and 90). Keep rows in the band with `distinct_detections >= ..._min_detections` (2).
6. Drop any `user_key` that has a notable from `Threat - HDSI RBA AI User Critical Risk Threshold Exceeded - Rule` in `index=notable` in the last 24 hours (macro `..._critical_rule`).

### Key Fields

| Field | Description | Example Value |
|---|---|---|
| `user_key` | Merged person key; suppression key | `jdoe` |
| `user` / `risk_object` | Raw identity with the most points | `CORP\jdoe` |
| `account` | `user_key` without host or domain; drilldown pre-filter | `jdoe` |
| `risk_object_values` | Every merged raw form | `CORP\jdoe`, `jdoe@corp.example` |
| `total_risk` / `risk_band` | 24 h total / always `medium` | `70` / `medium` |
| `distinct_detections` / `risk_event_count` | Distinct detections / risk events | `3` / `4` |
| `detection_list` | Up to 8 contributors with points, highest first | `First Seen Provider For User (20); Unsanctioned Web Access (15); ...` |
| `top_detection` / `top_detection_share` | Largest contributor and its % of the total | `High Volume Upload To AI Service` / `57` |
| `kill_chain_list` | AI kill-chain phases | `exfiltration, recon` |
| `contributing_mitre_attack` | Technique IDs of the contributors | `T1567`, `T1588.007` |
| `medium_risk_threshold` / `high_risk_threshold` / `min_detections` | Band edges and detection minimum used | `60` / `90` / `2` |
| `firstTime` / `lastTime` | First and last contributing risk event | `10/09/2026 08:12:00` |

### Thresholds

| Parameter | Default Value | Where | Notes |
|---|---|---|---|
| Lower band edge | `60` | `ai_detection_config` row `medium_risk_threshold` (common) | Must stay below `high_risk_threshold` |
| Upper band edge (exclusive) | `90` | `ai_detection_config` row `high_risk_threshold` (common) | Shared with AI-RISK-002 |
| Minimum distinct detections | `2` | `..._min_detections` | `1` alerts on the medium total alone |
| Critical rule for hand-off | `Threat - HDSI RBA AI User Critical Risk Threshold Exceeded - Rule` | `..._critical_rule` | Change only if AI-RISK-002 is renamed |

---

## Triage Steps

> **Estimated triage time:** 15-25 minutes

Use `$user_key$` and `$account$` from the notable.

The `tstats summariesonly=t` evidence searches read accelerated summaries only. In validation the most recent 15-30 minutes were not yet summarised on two tenants, so for very recent activity re-run them later, or with `summariesonly=f` over a short window.

### Step 1: Validate the notable

```spl
index=notable source IN ("Threat - HDSI RBA AI User Risk Threshold Exceeded - Rule", "Threat - HDSI RBA AI User Critical Risk Threshold Exceeded - Rule") earliest=-7d
| search user_key="$user_key$"
| table _time, source, user, user_key, total_risk, distinct_detections, detection_list, top_detection, top_detection_share, kill_chain_list
| sort - _time
```

- Confirm `user_key` is one real person; check `risk_object_values` for merged forms that belong to different people.
- Repeated medium notables on consecutive days for the same person are a trend worth escalating even if no single day reaches 90.

### Step 2: Understand the risk composition

This is the second drilldown (`Summarize AI risk by detection`).

```spl
| from datamodel:"Risk.All_Risk"
| search risk_object_type="user" risk_object="*$account$*" (source="* - HDSI AI * - Rule" OR detection_id="hdsi_ai_*") NOT source="* - HDSI AI Health * - Rule"
| `hdsi_rba_ai_user_risk_threshold_exceeded_user_key`
| search user_key="$user_key$"
| eval score=coalesce(calculated_risk_score, risk_score)
| stats count as risk_events sum(score) as total_risk values(ai_kill_chain_phase) as ai_kill_chain_phase values(provider) as providers values(risk_object) as risk_objects min(_time) as firstTime max(_time) as lastTime by source
| convert ctime(firstTime) ctime(lastTime)
| sort - total_risk
```

- A total built only from recon-phase web detections (unsanctioned access, first seen, multiple services) is usually shadow AI adoption: a policy and sanctioning issue.
- A total that includes an upload, DLP, agent or adversarial detection deserves that detection's own runbook.

### Step 3: Read the contributing events in time order

```spl
| from datamodel:"Risk.All_Risk"
| search risk_object_type="user" risk_object="*$account$*" (source="* - HDSI AI * - Rule" OR detection_id="hdsi_ai_*") NOT source="* - HDSI AI Health * - Rule"
| `hdsi_rba_ai_user_risk_threshold_exceeded_user_key`
| search user_key="$user_key$"
| eval score=coalesce(calculated_risk_score, risk_score)
| table _time, source, risk_object, score, ai_kill_chain_phase, provider, risk_message
| sort 0 _time
```

### Step 4: Review the raw AI web activity

`fillnull_value` keeps rows where only `site` (SSE app name) or only `url_domain` is mapped:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count sum(Web.bytes_out) as bytes_out min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url_domain=* OR Web.site=*) Web.user="*$account$*" by Web.user Web.src Web.url_domain Web.site
| rename Web.* as *
| eval ai_domain=lower(coalesce(nullif(url_domain,"unknown"), nullif(site,"unknown"))), ai_input_type=if(isnull(nullif(url_domain,"unknown")), "app", "host")
| `ai_domains_filter`
| eval mb_out=round(bytes_out/1024/1024, 2)
| convert ctime(firstTime) ctime(lastTime)
| sort - mb_out
| table firstTime, lastTime, user, src, ai_domain, provider, usage_type, count, mb_out
```

- Which providers, how often, how much uploaded? Are they sanctioned for this user?

### Step 5: Check all risk on the person and other AI notables

This is the third drilldown.

```spl
| from datamodel:"Risk.All_Risk"
| search risk_object_type="user" risk_object="*$account$*"
| `hdsi_rba_ai_user_risk_threshold_exceeded_user_key`
| search user_key="$user_key$"
| eval score=coalesce(calculated_risk_score, risk_score)
| stats count as risk_events sum(score) as total_risk values(risk_object) as risk_objects latest(risk_message) as latest_message by source
| sort - total_risk
```

```spl
index=notable source="Threat - HDSI RBA AI *" earliest=-7d
| search user_key="$user_key$" OR risk_entity="$account$" OR entity="$account$" OR risk_object="*$account$*"
| table _time, source, user, total_risk
```

### Step 6: Identify the user and check sanctioned status

```spl
| inputlookup identity_lookup_expanded
| search identity="$account$"
| table identity, first, last, email, managedBy, bunit, category, priority, watchlist, endDate
```

```spl
| inputlookup ai_sanctioned_entities
| search entity="*$account$*" OR entity="*"
| table entity_type, entity, provider, scope, expires, owner, reason, enabled, allow_key
```

### Step 7: Make a determination

- **True Positive:** unsanctioned AI use with a meaningful contributor (upload, DLP, risky access, agent misuse), or a policy violation the business wants addressed.
- **Benign True Positive:** authorised AI use not yet recorded in `ai_sanctioned_entities`.
- **False Positive:** merged identities that are different people, or an account that should be excluded.

---

## True Positive Indicators

- A data-exposure or risky-access detection is among the contributors (not only recon/web browsing).
- `top_detection_share` is moderate (no single detection dominates) and the phases progress (recon, then execution or exfiltration).
- The providers are unsanctioned or reached with a personal account.
- The same person returns to the medium band day after day, or has non-AI risk too.

---

## False Positive Scenarios

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Heavy user of an unsanctioned but harmless provider: Unsanctioned Web Access, First Seen Provider, Multiple Services, Usage Volume Anomaly and After Hours score the same browsing from different angles | High (early weeks) | Record sanctioned providers and users in `ai_sanctioned_entities` before enabling |
| One detection dominates the total (the top rule supplied 68-87% of qualifying totals in the proxy run) | Medium | Use `..._customizations`, e.g. `where top_detection_share<90` |
| Different people sharing an account name across domains or forests | Low | Switch `..._user_key` to `eval user_key=lower(trim(risk_object))` in **both** band rules |
| Service or automation account running AI tooling | Low-Medium | Add a pattern to `..._excluded_accounts` in **both** band rules |

---

## Response Actions

### If confirmed True Positive

1. **Contain:** block the unsanctioned providers for the user and revoke personal OAuth grants where present.
2. **Notify:** the user's manager; data governance if any data-exposure detection contributed.
3. **Investigate:** triage the top contributor with its own runbook; check whether the user later reaches AI-RISK-002.
4. **Remediate:** guide the user to sanctioned AI tooling and record the policy acknowledgement.
5. **Document:** attach the composition from Step 2 to the case.

### If Benign True Positive

1. Add the user, group or provider to `ai_sanctioned_entities` with a scope and `expires`.
2. Record the justification.
3. Close the notable as Benign True Positive.

---

## Tuning Guidance

### Reducing false positives

- Sanction approved AI use at the source first; it removes the activity from every contributing detection.
- Keep `..._filter`, `..._user_key`, `..._excluded_accounts` and `..._risk_index` identical to AI-RISK-002's copies (`hdsi_rba_ai_user_critical_risk_threshold_exceeded_*`). If they differ, the two rules total different events and the bands can overlap.
- The rule does not filter `tag="risk_suppression"`: in validation, adding it to the base search made Splunk return nothing on two tenants. If your tenant relies on that tag, add `| search NOT tag="risk_suppression"` **after** the base search in both band rules.
- Band edges are the `ai_detection_config` rows in the common package, not macros. Change them there, never in a copy of the search.

### Adjusting thresholds

Two to four weeks after the HDSI AI detections are enabled, profile daily per-person totals with the rule's own filters. Put `medium_risk_threshold` near p95 (not below 40) and `high_risk_threshold` near p99, at least 30 points above medium. Person-days at or above the new medium value divided by 14 is the expected daily notable count:

```spl
`hdsi_rba_ai_user_risk_threshold_exceeded_risk_index` risk_object_type="user" (source="* - HDSI AI * - Rule" OR detection_id="hdsi_ai_*") NOT source="* - HDSI AI Health * - Rule" NOT detection_id="hdsi_ai_health_*" risk_object=* NOT risk_object IN ("unknown","-","*$") earliest=-14d@d latest=@d
| `hdsi_rba_ai_user_risk_threshold_exceeded_user_key`
| where len(user_key)>0 AND NOT (`hdsi_rba_ai_user_risk_threshold_exceeded_excluded_accounts`) AND isnotnull(tonumber(risk_score))
| eval detection_key=coalesce(nullif(mvindex(detection_id,0),""), source)
| bin _time span=1d
| stats sum(risk_score) as day_total dc(detection_key) as detections by _time user_key
| where detections>=2
| stats count as person_days dc(user_key) as people perc90(day_total) as p90 perc95(day_total) as p95 perc99(day_total) as p99 max(day_total) as max_total
```

### Adding allowlist entries

```
entity_type,entity,provider,scope,expires,owner,reason,enabled,allow_key
user,<username>,<provider>,provider,<YYYY-MM-DD>,<your_name>,<justification>,1,<username>|<provider_lowercase>
```

---

## Related Detections

| Detection ID | Name | Relationship |
|---|---|---|
| AI-RISK-002 | HDSI RBA AI User Critical Risk Threshold Exceeded | Upper band of the same total; this rule defers to it |
| AI-RISK-003 | HDSI RBA AI Data Collection Kill Chain | Ordered collection-to-upload sequence |
| AI-RISK-004 | HDSI RBA AI Privilege Escalation Correlation | Privilege change followed by AI activity |
| AI-RISK-005 | HDSI RBA AI Multi-Vector Risk | Breadth across AI risk vectors |
| AI-001 to AI-046 | HDSI AI detections that score users | Contributors |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Model | ES risk index (`..._risk_index`, `index=risk`); `Risk.All_Risk` for drilldowns; `index=notable` for the hand-off guard |
| Required Fields | `source`, `risk_object`, `risk_object_type`, `risk_score`; context fields `detection_id`, `ai_kill_chain_phase`, `annotations.mitre_attack`, `mitre_attack`; on notables `user_key` (written by AI-RISK-002) |
| Contributors | At least two HDSI AI detections that score **users**. Host-only detections (DNS Queries To AI Domains, Access From Unmanaged Device, Local LLM Listening Port) never contribute |
| Companion rule | AI-RISK-002, deployed with the same filter, key, exclusion and index macros |
| Sourcetype Examples | N/A (reads risk events) |
| Acceleration | Not required for the rule. Triage Step 4 uses `tstats summariesonly=t` on Web |
| Lookups | `ai_detection_config` (rows `medium_risk_threshold`, `high_risk_threshold`). Triage uses `identity_lookup_expanded`, `ai_sanctioned_entities`, `ai_provider_domains` |
| Prerequisite package | `hdsi_ai_rba_common` |

### Validation (2026-10-09)

Read-only runs against 4 production ES tenants (Tenant A-D). No HDSI AI detection was deployed, so real runs returned 0 rows with no errors (Tenant A 7-25 s including the notable-index guard; others under 6 s). A proxy run over each tenant's real non-AI user risk (AI membership filter removed) found people in the band by total, and then with two or more rules: Tenant A 12,977 to 293, B 4 to 0, C 1,194 to 7, D 2 to 0. The two-detection gate removed 98-100% of single-rule totals. A 23-person synthetic test raised exactly the 6 expected medium notables (including UPN plus `DOMAIN\` merge and the inclusive 60 boundary). AI-RISK-002 on the same events raised exactly the 3 critical-band people, with no overlap, and an injected critical notable suppressed the matching medium notable.

---

## Revision History

| Date | Author | Change |
|---|---|---|
| 2026-02-13 | Brainstorm SOC | Initial creation |
| 2026-10-09 | Hurricane Labs | 1.1.0: rewritten for the released package. Stanza renamed to `Threat - HDSI RBA AI User Risk Threshold Exceeded - Rule`. Rebuilt as the medium band of a disjoint pair with AI-RISK-002 (60 to below 90, at least 2 distinct detections, skip users with a critical notable in 24 h). UPN/`DOMAIN\`/bare forms merged into `user_key`; placeholder, machine, service and shared accounts excluded; per-detection breakdown and top-contributor share in the notable; suppression changed from 4 h to 24 h on `user_key`; MITRE changed from T1078 to T1588.007. Notable only, no risk. Triage SPL rebuilt on `Risk.All_Risk` |
