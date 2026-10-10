# AI-RISK-004 - HDSI RBA AI Privilege Escalation Correlation

> **Detection ID:** AI-RISK-004
> **Package:** `hdsi_rba_ai_privilege_escalation_correlation` (v1.1.0, `deployment_type: global`)
> **Correlation search:** `Threat - HDSI RBA AI Privilege Escalation Correlation - Rule`
> **Status:** Active (ships with `enable_alerting: false`; enabling is a separately approved change)
> **Type:** Risk aggregator. Creates a notable (`action.notable = 1`), writes **no** risk (`action.risk = 0`)
> **Notable:** severity `high`, security domain `threat`, title `Privilege Escalation Followed By AI Activity (<risk_object>)`
> **Risk Score:** N/A. The `_risk` entry (user, 50) is kept for conformance only; with `action.risk = 0` nothing is written
> **MITRE ATT&CK:** T1098 Account Manipulation, T1134 Access Token Manipulation, T1548 Abuse Elevation Control Mechanism (Privilege Escalation); T1567 Exfiltration Over Web Service (Exfiltration)
> **Data Source:** ES risk index (`index=risk`); drilldowns use the `Risk.All_Risk` data model
> **Schedule:** `20 * * * *` (hourly at minute 20)
> **Lookback Window:** `-24h@h` to `now`
> **Suppression:** 24 hours (`86400s`) per `risk_entity`
> **Kill Chain Phase:** Privilege escalation followed by AI execution, staging, collection, exfiltration or lateral movement
> **Last Updated:** 2026-10-09

---

## Overview

This rule raises a high notable when an account receives risk from a **privilege-change** rule and then, in the same 24-hour risk window, AI-RBA risk whose **activity happened at or after** that change. Privilege-change rules cover admin role or group grants, elevation, token manipulation and exploitation for privilege escalation. Qualifying AI activity is execution, staging, collection, exfiltration or lateral movement.

The order is the point. An account that has just gained new rights and then drives AI agents, uploads data to AI services or stages models is what an insider abuse case or an account takeover looks like. Ordinary AI use by an admin who has had the same rights for months does not fire.

Ordering is fail-closed: when an AI rule's activity time is only known coarsely (a date, or the start of its search window), the earliest possible time is used, so activity from before the privilege change is never counted as after it.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique ID | T1098, T1134, T1548, T1567 (annotation and `mitre_attack` result field) |
| Technique Name | Account Manipulation; Access Token Manipulation; Abuse Elevation Control Mechanism; Exfiltration Over Web Service |
| Tactic | Privilege Escalation, Persistence, Defense Evasion; Exfiltration |
| Sub-technique | The privilege techniques matched on the account are listed per notable in `priv_technique_list` (e.g. T1098.003, T1134.001) |

---

## Detection Logic

### Plain English

1. Read `index=risk` for `-24h@h` to `now`, `risk_object_type` in `..._object_types` (ships as `user`), tenant filter applied.
2. Build `risk_entity`: the lower-case `risk_object` with any `DOMAIN\` prefix and `@domain` suffix removed, so the privilege rule's `CORP\jdoe` and the AI rule's `jdoe@corp.example` join. Drop placeholders, `system`, `nt authority` and anything matching `..._nonhuman_regex` (NT SERVICE / NT AUTHORITY accounts, Entra service principals, GUIDs, `HOST$`).
3. Classify each event:
   - **AI signal:** an HDSI AI detection (by `detection_id` `hdsi_ai_*`, or a `* - HDSI AI * - Rule` source) whose `ai_kill_chain_phase` is in `..._ai_phases` and whose `detection_id` is not in `..._ai_excluded_detections`. `HDSI RBA AI` aggregators never count.
   - **Privilege signal:** a non-AI rule whose `annotations.mitre_attack` / `mitre_attack` contains a technique matching `..._priv_techniques` (T1068, T1134.x, T1484.x, T1548.x, T1611, T1098.002, T1098.003, T1098.007), or whose name matches `..._priv_rule_regex`.
4. Time each event:
   - Privilege time = the privilege rule's `firstTime` if it parses; else the result `_time` inside the rule's search window; else the end of that window.
   - AI time = the AI rule's `lastTime` with a time of day; else the result `_time` inside its window; else the start of the day of a date-only `lastTime`; else the start of its search window. No time = not counted.
5. Keep AI events at or after the account's first privilege time. Sum privilege and AI risk per `risk_entity`.
6. Fire when there is at least one privilege signal, at least one AI signal and the summed AI risk is at least `..._min_ai_risk` (20).

### Key Fields

| Field | Description | Example Value |
|---|---|---|
| `risk_object` / `user` | Account (first raw form seen) | `CORP\jdoe` |
| `risk_entity` | Bare lower-case join key; the suppression key | `jdoe` |
| `risk_objects` | All raw forms merged | `CORP\jdoe`, `jdoe@corp.example` |
| `priv_signals` / `priv_risk` | Privilege-change risk events and their summed score | `1` / `40` |
| `priv_detection_list` / `priv_technique_list` | Privilege rules and matched techniques | `... Admin Role Granted ...` / `T1098.003` |
| `ai_signals` / `ai_risk` | Qualifying AI risk events and their summed score | `2` / `55` |
| `ai_detection_list` / `ai_detection_ids` / `ai_phase_list` | AI rules, ids and phases that qualified | `hdsi_ai_high_volume_upload_to_ai_service` / `exfiltration` |
| `gap_minutes` | First privilege time to first qualifying AI activity (can exceed 1,440 when a multi-day privilege rule supplied an old `firstTime`) | `95` |
| `time_basis` | How each side was timed (`firstTime`, `lastTime`, `result _time`, `search window end/start`) | `privilege: firstTime; AI: lastTime` |
| `firstTime` / `lastTime` | First privilege time / last AI activity | `2026-10-09 08:05:00 UTC` |

### Thresholds

| Parameter | Default Value | Macro | Notes |
|---|---|---|---|
| Minimum AI risk after the change | `20` | `hdsi_rba_ai_privilege_escalation_correlation_min_ai_risk` | Stops a single routine 10-point AI event from firing |
| AI phases | execution, staging, collection, exfiltration, lateral_movement | `..._ai_phases` | `recon` and `initial_access` excluded |
| Excluded AI detections | `hdsi_ai_privileged_account_service_usage` | `..._ai_excluded_detections` | It scores any AI visit by a privileged account, so it would turn "new admin opens a chat assistant" into a notable |
| Privilege techniques | see step 3 | `..._priv_techniques` | T1078, bare T1098 and TA0004 are deliberately excluded (tens of thousands of routine login and MFA events per week in live data) |
| Object types | `"user"` | `..._object_types` | Add `"system"` only if privilege and AI rules name hosts the same way |

---

## Triage Steps

> **Estimated triage time:** 30-45 minutes

Replace `$risk_entity$` with the notable's `risk_entity` (bare, lower case).

The `tstats summariesonly=t` evidence searches read accelerated summaries only. In validation the most recent 15-30 minutes were not yet summarised on two tenants, so for very recent activity re-run them later, or with `summariesonly=f` over a short window.

### Step 1: Validate the notable

```spl
index=notable source="Threat - HDSI RBA AI Privilege Escalation Correlation - Rule" earliest=-7d
| search risk_entity="$risk_entity$"
| table _time, risk_object, risk_objects, priv_detection_list, priv_technique_list, priv_risk, ai_detection_list, ai_phase_list, ai_risk, gap_minutes, time_basis, firstTime, lastTime
```

- Confirm the account is a person, not a service principal, role group or IAM automation user that slipped past `_nonhuman_regex`.
- Read `time_basis`: `firstTime`/`lastTime` on both sides means the order is exact; `search window end` on the privilege side means the change may have happened up to one rule window earlier.

### Step 2: Build the account's risk timeline

This combines the two drilldowns, with an AI/non-AI marker.

```spl
| from datamodel:"Risk.All_Risk"
| search risk_object="*$risk_entity$*"
| eval risk_entity=replace(mvindex(split(lower(trim(mvindex(risk_object,0))),urldecode("%5C")),-1),"@.*","")
| search risk_entity="$risk_entity$"
| eval family=case(match(source, "HDSI RBA AI "), "aggregator", match(mvindex(detection_id,0), "^hdsi_ai_") OR match(source, " - HDSI AI .+ - Rule"), "AI", true(), "non-AI")
| table _time, family, source, risk_object, risk_object_type, risk_score, ai_kill_chain_phase, detection_id, annotations.mitre_attack, firstTime, lastTime, risk_message
| sort 0 _time
```

- Find the privilege change (non-AI rows) and confirm what was granted: which role or group, by whom, from where.
- Then read the AI rows after it: which phase, which provider or tool, which host.

### Step 3: Verify the privilege change at the source

Open the privilege rule's own drilldown, or query the Change data model for the account:

```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime values(All_Changes.action) as action values(All_Changes.result) as result values(All_Changes.object_attrs) as object_attrs from datamodel=Change.All_Changes where (All_Changes.user="*$risk_entity$*" OR All_Changes.object="*$risk_entity$*") by All_Changes.user All_Changes.object All_Changes.object_category All_Changes.src All_Changes.vendor_product
| rename All_Changes.* as *
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

- Was the change approved (ticket, PIM justification, change window)? Who made it (`user` = actor, `object` = target)?
- Self-granted rights, a grant from an unusual source, or a grant outside business hours raise the priority.

### Step 4: Review the AI activity after the change

For web/SSE AI use (`fillnull_value` keeps SSE rows that only map `site`):

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count sum(Web.bytes_out) as bytes_out min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url_domain=* OR Web.site=*) Web.user="*$risk_entity$*" by Web.user Web.src Web.url_domain Web.site
| rename Web.* as *
| eval ai_domain=lower(coalesce(nullif(url_domain,"unknown"), nullif(site,"unknown"))), ai_input_type=if(isnull(nullif(url_domain,"unknown")), "app", "host")
| `ai_domains_filter`
| eval mb_out=round(bytes_out/1024/1024, 2)
| convert ctime(firstTime) ctime(lastTime)
| sort - mb_out
| table firstTime, lastTime, user, src, ai_domain, provider, count, mb_out
```

For AI tools on endpoints:

```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where Processes.user="*$risk_entity$*" by Processes.dest Processes.user Processes.process_name
| rename Processes.* as *
| eval process_name_lc=lower(process_name)
| `ai_process_enrich`
| where enabled=1
| convert ctime(firstTime) ctime(lastTime)
| table firstTime, lastTime, dest, user, process_name, tool, provider, count, process
```

- Did the AI activity use the new rights (agent running with admin tokens, data pulled from systems the account could not read before)?
- Exfiltration-phase AI after a privilege grant is the most serious combination.

### Step 5: Identify the user

```spl
| inputlookup identity_lookup_expanded
| search identity="$risk_entity$"
| table identity, first, last, email, managedBy, bunit, category, priority, watchlist, endDate
```

- Is the user expected to hold the new role? Are they an administrator who routinely activates PIM roles?

### Step 6: Determine sanctioned status

```spl
| inputlookup ai_sanctioned_entities
| search entity="*$risk_entity$*" OR entity="*"
| table entity_type, entity, provider, scope, expires, owner, reason, enabled, allow_key
```

### Step 7: Make a determination

- **True Positive:** an unexpected or unapproved privilege change followed by AI collection, exfiltration or agent execution that uses the new access.
- **Benign True Positive:** an approved PIM activation or role grant followed by routine, sanctioned AI tooling.
- **False Positive:** the "privilege" rule is about privileged accounts rather than privilege changes, or the account is non-human.

---

## True Positive Indicators

- The privilege change was not approved, was self-granted, or came from an unusual source or time.
- The AI activity is in the `exfiltration` or `collection` phase, or an agent framework ran under the new rights.
- `gap_minutes` is short (minutes to a few hours).
- The account also has a Data Collection Kill Chain (AI-RISK-003) or Multi-Vector (AI-RISK-005) notable.
- Other non-AI risk on the account (suspicious logins, MFA fatigue) before the change suggests takeover.

---

## False Positive Scenarios

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Routine PIM activation or admin-role grant, then ordinary AI use (an AI coding agent, after-hours AI use, usage anomalies). PIM and admin-role rules were the largest privilege source on Tenant A, 12-14 accounts a week each | High | Exclude the PIM rule or admin accounts in `..._filter`, or add general-use rules such as `hdsi_ai_after_hours_service_usage` to `..._ai_excluded_detections` |
| Broad rule-name match, e.g. a "privileged account passwords changed" rule (seen on Tenant D) | Medium | Exclude that source in `..._filter` |
| Non-human objects scored as `user` (role groups, service principals, IAM service users) | Low | Extend `..._nonhuman_regex` with tenant naming, e.g. `^svc[_-]` |
| Mis-annotated rule (a web-attack rule carrying T1134.004 on Tenant A) | Low while `system` is not correlated | Exclude it in `..._filter` before adding `system` |
| Different people sharing a bare account name across domains or forests | Low | Review in multi-forest tenants |

---

## Response Actions

### If confirmed True Positive

1. **Contain:** revoke the new role or group membership, end active sessions and reset credentials. Block the AI provider or stop the agent process if exfiltration is ongoing.
2. **Notify:** identity administrators, the account owner's manager, and incident response.
3. **Investigate:** who granted the privilege and how; what the AI activity touched with the new rights; whether other accounts received the same grant.
4. **Remediate:** require approval and justification for the role (PIM), restrict AI tooling for privileged sessions, rotate secrets the account could reach.
5. **Document:** record the timeline from Step 2 and the change evidence from Step 3.

### If Benign True Positive

1. Sanction the admin's AI use in `ai_sanctioned_entities`, or add a narrow `..._filter` exclusion for the routine privilege source.
2. Record the justification and an expiry.
3. Close the notable as Benign True Positive.

---

## Tuning Guidance

### Reducing false positives

- Decide before enabling how routine PIM and admin-role activity is handled: exclude it in `..._filter`, or accept it and exclude general-use AI rules in `..._ai_excluded_detections`.
- Keep `hdsi_ai_privileged_account_service_usage` excluded.
- Use `..._customizations` for post-aggregation rules, e.g. `where total_risk>=80`.

### Adjusting thresholds

Size the daily privilege pool (accounts that could fire) with the rule's own classification:

```spl
index=risk risk_object_type IN (`hdsi_rba_ai_privilege_escalation_correlation_object_types`) `hdsi_rba_ai_privilege_escalation_correlation_filter`
| eval risk_entity=replace(mvindex(split(lower(trim(mvindex(risk_object,0))),urldecode("%5C")),-1),"@.*",""), rule_name=coalesce(mvindex(source,0),mvindex(search_name,0))
| where isnotnull(risk_entity) AND risk_entity!="" AND NOT in(risk_entity,"unknown","-","n/a","na","null","none","system","local system","nt authority") AND NOT match(lower(mvindex(risk_object,0)),`hdsi_rba_ai_privilege_escalation_correlation_nonhuman_regex`)
| where NOT match(rule_name,"HDSI RBA AI ") AND NOT match(coalesce(mvindex(detection_id,0),"-"),"^hdsi_ai_") AND NOT match(rule_name," - HDSI AI .+ - Rule")
| eval mitre_list=split(replace(upper(mvjoin(mvappend('annotations.mitre_attack',mitre_attack),",")),"[^A-Z0-9.,]",""),","), priv_tech=mvfilter(match(mitre_list,`hdsi_rba_ai_privilege_escalation_correlation_priv_techniques`))
| where mvcount(priv_tech)>0 OR match(rule_name,`hdsi_rba_ai_privilege_escalation_correlation_priv_rule_regex`)
| bin _time span=1d
| stats dc(risk_entity) as priv_accounts values(rule_name) as priv_rules by _time
```

Once the AI rules have run for a week, set `..._min_ai_risk` near the median daily qualifying AI risk per account, never below 20:

```spl
index=risk risk_object_type="user" detection_id="hdsi_ai_*" ai_kill_chain_phase IN (`hdsi_rba_ai_privilege_escalation_correlation_ai_phases`) NOT detection_id IN (`hdsi_rba_ai_privilege_escalation_correlation_ai_excluded_detections`)
| bin _time span=1d
| stats sum(risk_score) as ai_risk by _time risk_object
| stats perc50(ai_risk) as p50 perc90(ai_risk) as p90 by _time
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
| AI-016 | Privileged Account Service Usage | Excluded by default; scores AI use by any privileged account |
| AI-035 | AI-Assisted Lateral Movement | `lateral_movement` AI signal |
| AI-039, AI-037, AI-046, AI-004, AI-008 | Agent Autonomous Action; Agent Framework; MCP Server; Unsanctioned CLI; Scripted CLI | `execution` AI signals |
| AI-007, AI-044, AI-027, AI-032, AI-020, AI-038 | Upload, gradual exfiltration, personal email, model exfiltration, DLP (AI-020 is incubating: not released) | `exfiltration` AI signals |
| AI-RISK-003 | HDSI RBA AI Data Collection Kill Chain | Ordered collection-to-upload chain on the same account |
| AI-RISK-005 | HDSI RBA AI Multi-Vector Risk | Breadth of AI risk on the same account |
| AI-RISK-001 / AI-RISK-002 | HDSI RBA AI User Risk Threshold Exceeded | Score-based view |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Model | ES risk index (`index=risk`); `Risk.All_Risk` for drilldowns |
| Required Fields | `risk_object`, `risk_object_type`, `risk_score`, `source`/`search_name`, `annotations.mitre_attack`/`mitre_attack`, `firstTime`, `lastTime`, `info_min_time`, `info_max_time`; on AI events `detection_id` and `ai_kill_chain_phase` (an AI event without a phase never counts) |
| Contributors | At least one **non-AI** privilege-change rule writing user risk (AD privileged-group changes, Entra/O365 role grants, PIM, cloud IAM grants, UAC bypass/token manipulation), plus the `hdsi_ai_*` risk rules |
| Sourcetype Examples | N/A (reads risk events). Triage uses the Change, Web and Endpoint data models |
| CIM Compliance | Privilege rules should carry ATT&CK annotations or descriptive names |
| Acceleration | Not required for the rule. Triage Steps 3-4 use `tstats summariesonly=t` |
| Lookups | None at run time. Triage uses `identity_lookup_expanded`, `ai_sanctioned_entities`, `ai_provider_domains`, `ai_tool_processes` |
| Prerequisite package | `hdsi_ai_rba_common` (required by the AI contributors) |

### Validation (2026-10-09)

Read-only runs against 4 production ES tenants (Tenant A-D). No HDSI AI rule was deployed, so there were no AI risk events; real runs returned 0 rows.

| Tenant | Privilege-change risk (7 d) | Parse (search + 2 drilldowns) | Scheduled window | Real privilege events + one synthetic AI follow-up per account (7 d) |
|---|---|---|---|---|
| A | 9 rules, 2-16 accounts/day | OK | 0 rows, 8.8 s | 50 notables (about 7 a day): the ceiling if every privileged account used AI afterwards |
| B | 1 rule (cloud IAM grant), 0-2 accounts/day | OK | 0 rows, 2.9 s | 6 notables (IAM service users) |
| C | none | OK | 0 rows, 3.5 s | 0: no privilege source, so this rule cannot fire there today |
| D | 7 rules, 0-7 accounts/day | OK | 0 rows, 1.4 s | 14 notables |

Two synthetic tests (34 and 22 events) produced exactly the expected notables and suppressed AI activity before the privilege change, date-only and missing activity times, recon-only AI, T1078-only "privilege", AI risk below 20, the excluded privileged-usage rule, non-human objects, aggregator events and `system` objects.

---

## Revision History

| Date | Author | Change |
|---|---|---|
| 2026-03-04 | Hurricane Labs | Initial runbook |
| 2026-10-09 | Hurricane Labs | 1.1.0: rewritten for the released package. Stanza renamed to `Threat - HDSI RBA AI Privilege Escalation Correlation - Rule`. The previous AI test (`search_name` starting `HDSI AI`) never matched real names, so the rule could not fire. Now: AI events identified by `detection_id`/`ai_kill_chain_phase`, privilege events by specific ATT&CK techniques or rule name (T1078, bare T1098 and TA0004 removed), fail-closed time ordering from `firstTime`/`lastTime` and search windows, DOMAIN/UPN identity join, non-human objects dropped, privileged-usage rule excluded, minimum AI risk 20, hourly over `-24h@h`, 24 h suppression per `risk_entity`. Notable only, no risk. Triage SPL rebuilt on `Risk.All_Risk` |
