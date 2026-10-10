# AI-RISK-002 - HDSI RBA AI User Critical Risk Threshold Exceeded

> **Detection ID:** AI-RISK-002
> **Package:** `hdsi_rba_ai_user_critical_risk_threshold_exceeded` (v1.1.0, `deployment_type: global`)
> **Correlation search:** `Threat - HDSI RBA AI User Critical Risk Threshold Exceeded - Rule`
> **Status:** Active (ships with `enable_alerting: false`; enable together with AI-RISK-001 as one separately approved change)
> **Type:** Risk aggregator. Creates a notable (`action.notable = 1`), writes **no** risk (`action.risk = 0`)
> **Notable:** severity `high`, security domain `threat`, title `AI User Critical Risk Threshold Exceeded (<user>)`
> **Risk Score:** N/A. The `_risk` entry (user, 50) is kept for conformance only; nothing is written
> **MITRE ATT&CK:** T1588.007 Obtain Capabilities: Artificial Intelligence (Resource Development). Contributing techniques per notable in `contributing_mitre_attack`
> **Data Source:** ES risk index (`index=risk`, macro `..._risk_index`); drilldowns use the `Risk.All_Risk` data model
> **Schedule:** `12-59/15 * * * *` (every 15 minutes, offset 12)
> **Lookback Window:** `-24h@m` to `now` (rolling 24 hours)
> **Suppression:** 24 hours (`86400s`) per `user_key`
> **Kill Chain Phase:** N/A (aggregation layer; phases listed per notable)
> **Last Updated:** 2026-10-09

---

## Overview

This is the upper band of the HDSI AI user threshold pair. It raises a high notable when one person's HDSI AI risk in a rolling 24 hours reaches the critical threshold: `high_risk_threshold` in the common `ai_detection_config` lookup, default **90**. One detection is enough (`..._min_detections` = 1), so a repeated high-severity detection can reach it on its own.

It reads the user risk events that the HDSI AI detections write and adds a person's UPN, `DOMAIN\account` and bare account forms together, because web and SSE detections score the UPN while endpoint detections score the account name. Placeholder, machine, OS service and unqualified built-in accounts are never totalled: each would merge activity from many hosts into one fleet-wide pseudo-user.

The notable lists every contributing detection with its points, the AI kill-chain phases and the ATT&CK techniques, so the analyst sees at once why the user crossed the line. AI-RISK-001 (medium) covers the band below, with the same identity key, exclusions and risk index.

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

1. Read `index=risk` (macro `..._risk_index`) for `risk_object_type="user"` events whose `source` matches `* - HDSI AI * - Rule` or whose `detection_id` starts with `hdsi_ai_`. The health checks (`* - HDSI AI Health * - Rule`, `hdsi_ai_health_*`) are excluded. `risk_object` must be set and must not be `unknown`, `-` or end in `$`. The tenant filter is applied inline.
2. Build `user_key` with `..._user_key`: lower-case `risk_object` with any `@domain` and `DOMAIN\` removed. Built-in local accounts (`administrator`, `admin`, `guest`, `defaultaccount`, `wdagutilityaccount`) keep their qualifier, written `host/administrator`, so they never merge across machines.
3. Drop accounts matched by `..._excluded_accounts`: placeholders and masks, `$` computer accounts, OS service identities (`SYSTEM`, `LOCAL/NETWORK SERVICE`, `NT AUTHORITY\*`, `NT SERVICE\*`, `IIS APPPOOL\*`, `DWM-n`, `UMFD-n`), `root`, `nobody`, `daemon`, `krbtgt`, and bare unqualified built-ins.
4. Sum `risk_score` per `user_key` and contributing detection, then per user. The notable `user` is the raw risk object that carried the most points.
5. Look up `high_risk_threshold` in `ai_detection_config` (default 90). Keep users with `total_risk >= high_risk_threshold` and at least `..._min_detections` (1) detections.

### Key Fields

| Field | Description | Example Value |
|---|---|---|
| `user` / `risk_object` | Raw identity with the most points | `jdoe@corp.example` |
| `user_key` | Merged person key; the suppression key, and the key AI-RISK-001 uses for hand-off | `jdoe` |
| `account` | `user_key` without host or domain; used by the drilldowns to pre-filter | `jdoe` |
| `risk_objects` | Every merged raw form | `jdoe@corp.example`, `CORP\jdoe` |
| `total_risk` / `high_risk_threshold` | 24 h total and the threshold it crossed | `105` / `90` |
| `detection_count` / `risk_event_count` | Distinct detections / risk events | `3` / `5` |
| `top_detection_risk` | Points from the largest contributor | `45` |
| `detection_list` | Up to 8 contributors with points, highest first | `HDSI AI High Volume Upload To AI Service (45); ...` |
| `phase_list` | AI kill-chain phases | `exfiltration, recon` |
| `contributing_mitre_attack` | Technique IDs of the contributors | `T1567` |
| `ai_providers` | Up to 10 providers | `OpenAI`, `Anthropic` |
| `firstTime` / `lastTime` | First and last contributing risk event | `2026-10-09 08:12:00` |

### Thresholds

| Parameter | Default Value | Where | Notes |
|---|---|---|---|
| Critical threshold | `90` | `ai_detection_config` row `high_risk_threshold` (common) | Shared with AI-RISK-001 (upper edge of its band) |
| Minimum detections | `1` | `..._min_detections` | Raising it leaves single-detection critical totals with no notable from either rule |
| Suppression | 24 h per `user_key` | savedsearches.conf | One notable per person per day |

Per-event HDSI AI scores are modest (roughly 10 to 80), so 90 normally needs several detections in a day (for example unsanctioned web access + first-seen provider + high-volume upload + after hours), or a repeated high-severity detection such as AI-Assisted Lateral Movement.

---

## Triage Steps

> **Estimated triage time:** 20-40 minutes

Use `$user_key$` and `$account$` from the notable.

The `tstats summariesonly=t` evidence searches read accelerated summaries only. In validation the most recent 15-30 minutes were not yet summarised on two tenants, so for very recent activity re-run them later, or with `summariesonly=f` over a short window.

### Step 1: Validate the notable and the band hand-off

```spl
index=notable source IN ("Threat - HDSI RBA AI User Critical Risk Threshold Exceeded - Rule", "Threat - HDSI RBA AI User Risk Threshold Exceeded - Rule") earliest=-7d
| search user_key="$user_key$"
| table _time, source, user, user_key, risk_objects, total_risk, detection_count, detection_list, phase_list, ai_providers
| sort - _time
```

- Confirm `user_key` is one real person. If `risk_objects` mixes two people (same account name in two domains) or a shared account (`kiosk`, `shared_operator`), treat it as a tuning case.
- A medium notable (AI-RISK-001) earlier the same day followed by this one is an escalation, not a duplicate.

### Step 2: Understand the risk composition

This is the second drilldown (`Summarize HDSI AI risk by detection`).

```spl
| from datamodel:"Risk.All_Risk"
| search risk_object_type="user" risk_object="*$account$*" (source="* - HDSI AI * - Rule" OR detection_id="hdsi_ai_*") NOT source="* - HDSI AI Health * - Rule" NOT detection_id="hdsi_ai_health_*"
| `hdsi_rba_ai_user_critical_risk_threshold_exceeded_user_key`
| search user_key="$user_key$"
| stats count as risk_events sum(risk_score) as total_risk values(ai_kill_chain_phase) as phases values(provider) as providers values(risk_object) as risk_objects min(_time) as firstTime max(_time) as lastTime by source
| convert ctime(firstTime) ctime(lastTime)
| sort - total_risk
```

- One detection supplying most of the total (a repeated lateral-movement or upload event) needs that detection's own runbook first.
- Several detections across phases (recon, then execution, then exfiltration) is a progression: read Step 3 in time order.

### Step 3: Read the contributing events in time order

This is the first drilldown.

```spl
| from datamodel:"Risk.All_Risk"
| search risk_object_type="user" risk_object="*$account$*" (source="* - HDSI AI * - Rule" OR detection_id="hdsi_ai_*") NOT source="* - HDSI AI Health * - Rule" NOT detection_id="hdsi_ai_health_*"
| `hdsi_rba_ai_user_critical_risk_threshold_exceeded_user_key`
| search user_key="$user_key$"
| table _time, source, risk_object, risk_score, ai_kill_chain_phase, provider, risk_message
| sort 0 _time
```

### Step 4: Review the raw AI activity

Web and SSE activity (`fillnull_value` keeps rows where only `site` or only `url_domain` is mapped):

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

AI tools on endpoints:

```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where Processes.user="*$account$*" by Processes.dest Processes.user Processes.process_name
| rename Processes.* as *
| eval process_name_lc=lower(process_name)
| `ai_process_enrich`
| where enabled=1
| convert ctime(firstTime) ctime(lastTime)
| table firstTime, lastTime, dest, user, process_name, tool, provider, count, process
```

### Step 5: Check all risk on the person (AI and non-AI)

This is the third drilldown.

```spl
| from datamodel:"Risk.All_Risk"
| search risk_object_type="user" risk_object="*$account$*"
| `hdsi_rba_ai_user_critical_risk_threshold_exceeded_user_key`
| search user_key="$user_key$"
| eval family=if(match(source, " - HDSI (RBA )?AI "), "HDSI AI", "other")
| stats count as risk_events sum(risk_score) as total_risk values(risk_object) as risk_objects by family source
| sort - total_risk
```

- Non-AI risk (suspicious logins, malware, privilege changes) alongside AI risk changes the case from policy to security incident.
- Also check AI-RISK-003, AI-RISK-004 and AI-RISK-005 notables for the same person.

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

- **True Positive:** sustained unsanctioned AI use with data exposure, risky access or adversarial indicators, or a single high-severity detection that is confirmed.
- **Benign True Positive:** a heavy but authorised AI user whose tools are not yet in `ai_sanctioned_entities` (the most common case in the first weeks).
- **False Positive:** two people or a shared account merged under one `user_key`, or a service account that should be excluded.

---

## True Positive Indicators

- `phase_list` includes `exfiltration`, `collection` or `lateral_movement`, not only `recon`.
- An upload, DLP or model-exfiltration detection is among the top contributors.
- The providers are unsanctioned or reached with a personal account.
- The user is departing, on a watchlist, or in a sensitive business unit.
- There is non-AI risk on the same person in Step 5.

---

## False Positive Scenarios

| Scenario | Likelihood | Mitigation |
|---|---|---|
| A user's first heavy week with a new AI tool: unsanctioned access, first seen, burst, multiple services, upload and after-hours fire together | High (early weeks) | Load sanctioned tools into `ai_sanctioned_entities` before enabling |
| Automation or service account running AI agents or CLIs. In an all-rule stress test, service-like keys were 2 of 104 keys at or above 90 on Tenant A and 5 of 19 on Tenant C | Medium | Decide account by account; add a pattern to `..._excluded_accounts` in **both** band rules, e.g. `OR match(user_key, "^svc[_.-]")` |
| Different people sharing an account name across email domains or forests | Low | Switch `..._user_key` to `eval user_key=lower(trim(risk_object))` in both band rules |
| Generic shared names not on the exclusion list (`kiosk`, `shared_operator`) | Low | Add them to `..._excluded_accounts` in both rules |
| A domain built-in scored as both `EXAMPLE\Administrator` and `administrator@example.com` is split across two keys | Low (missed total, not a false alert) | Use the alternative `..._user_key` in the package README, in both rules |

---

## Response Actions

### If confirmed True Positive

1. **Contain:** block the unsanctioned providers for the user, revoke personal OAuth grants, and stop AI agents or local runtimes on the user's hosts.
2. **Notify:** the user's manager and data governance; incident response if non-AI risk is also present.
3. **Investigate:** triage each top contributor with its own runbook (Related Detections), and review data that may have been uploaded.
4. **Remediate:** move the user to sanctioned AI tooling, rotate exposed secrets, enforce DLP on the AI path.
5. **Document:** attach the composition from Step 2 to the case.

### If Benign True Positive

1. Add the user, group or provider to `ai_sanctioned_entities` with a scope and `expires`, so the contributors stop scoring.
2. Record the justification.
3. Close the notable as Benign True Positive.

---

## Tuning Guidance

### Reducing false positives

- Sanction approved AI use at the source first.
- Any change to `..._filter`, `..._user_key`, `..._excluded_accounts` or `..._risk_index` must be made identically in AI-RISK-001 (`hdsi_rba_ai_user_risk_threshold_exceeded_*`), or the bands overlap.
- Keep this stanza name and the `user_key` field in the notable: AI-RISK-001 looks up this rule's notables by `source` and `user_key`. `..._customizations` may filter rows but must not drop or rewrite `user_key`.
- Suppressed risk events are counted: the rule does not filter `tag="risk_suppression"` (on two validation tenants that filter made the whole search return nothing). Exclude a suppressed user with `..._filter`.

### Adjusting thresholds

After two weeks of detection data, profile daily totals with the rule's own filters and set `high_risk_threshold` near the 99th to 99.5th percentile, keeping `medium_risk_threshold` below it. `ge90 / 14` is the expected notables per day:

```spl
`hdsi_rba_ai_user_critical_risk_threshold_exceeded_risk_index` risk_object_type="user" source="* - HDSI AI * - Rule" NOT source="* - HDSI AI Health * - Rule"
| `hdsi_rba_ai_user_critical_risk_threshold_exceeded_user_key`
| where len(user_key)>0 AND NOT (`hdsi_rba_ai_user_critical_risk_threshold_exceeded_excluded_accounts`)
| bin _time span=1d
| stats sum(risk_score) as total_risk dc(source) as detections by _time user_key
| stats count as user_days perc90(total_risk) as p90 perc99(total_risk) as p99 perc99.5(total_risk) as p995 max(total_risk) as max count(eval(total_risk>=60)) as ge60 count(eval(total_risk>=90)) as ge90
```

Change the value in the common `ai_detection_config` lookup (row `high_risk_threshold`), never in a copy of the search.

### Adding allowlist entries

```
entity_type,entity,provider,scope,expires,owner,reason,enabled,allow_key
user,<username>,<provider>,provider,<YYYY-MM-DD>,<your_name>,<justification>,1,<username>|<provider_lowercase>
```

---

## Related Detections

| Detection ID | Name | Relationship |
|---|---|---|
| AI-RISK-001 | HDSI RBA AI User Risk Threshold Exceeded (medium) | Lower band of the same total; shares key, exclusions and thresholds |
| AI-RISK-003 | HDSI RBA AI Data Collection Kill Chain | Ordered collection-to-upload sequence for the same user |
| AI-RISK-004 | HDSI RBA AI Privilege Escalation Correlation | Privilege change followed by AI activity |
| AI-RISK-005 | HDSI RBA AI Multi-Vector Risk | Breadth across AI risk vectors |
| AI-001 to AI-046 | HDSI AI detections that score users | Contributors; triage the top contributor with its own runbook |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Model | ES risk index (`..._risk_index`, `index=risk`); `Risk.All_Risk` for drilldowns. Change both together if risk is written to another index |
| Required Fields | `source`, `risk_object`, `risk_object_type`, `risk_score`; context fields `ai_kill_chain_phase`, `annotations.mitre_attack`, `mitre_attack`, `provider`, `provider_list`, `detection_id` |
| Contributors | HDSI AI detections that score **users**. Host-only detections (DNS Queries To AI Domains, Access From Unmanaged Device, Local LLM Listening Port) never contribute; a DNS-only deployment never reaches this rule |
| Sourcetype Examples | N/A (reads risk events) |
| CIM Compliance | Contributors should score a consistent identity; the key merges UPN, `DOMAIN\` and bare forms but not different local parts (`jsmith` vs `john.smith@...`) |
| Acceleration | Not required for the rule. Triage Step 4 uses `tstats summariesonly=t` |
| Lookups | `ai_detection_config` (row `high_risk_threshold`). Triage uses `identity_lookup_expanded`, `ai_sanctioned_entities`, `ai_provider_domains`, `ai_tool_processes` |
| Prerequisite package | `hdsi_ai_rba_common` |

### Validation (2026-10-09)

Read-only runs against 4 production ES tenants (Tenant A-D). The search and all 3 drilldowns parse everywhere; real 24 h and 7 d runs returned 0 rows (no HDSI AI risk deployed) in 1-7 s. A "real-shape" run over each tenant's non-AI user risk, with the AI membership filter removed, found 105 users at or above 90 on Tenant A (none of them a built-in or service pseudo-user after the exclusions), 16 on B, 19 on C and 0 on D. A 13-case synthetic test gave identical, expected results on all four tenants (three identity forms merged to one notable; per-host built-ins kept separate; placeholders, machines, OS service accounts, health checks, aggregators and system objects dropped). Expected volume once user-scoring HDSI AI detections run: Tenant A 0-2 notables a day, Tenant B 0, Tenant C 1-5, Tenant D 0.

---

## Revision History

| Date | Author | Change |
|---|---|---|
| 2026-02-13 | Brainstorm SOC | Initial creation |
| 2026-10-09 | Hurricane Labs | 1.1.0: rewritten for the released package. Stanza renamed to `Threat - HDSI RBA AI User Critical Risk Threshold Exceeded - Rule`. Membership by `source` pattern or `detection_id`, health checks excluded, UPN/`DOMAIN\`/bare forms merged into `user_key`, placeholder/machine/service/unqualified built-in accounts excluded, per-host built-in keys, per-detection breakdown in the notable, risk index as a macro, suppression changed from 2 h on `user` to 24 h on `user_key`, MITRE T1588.007. Band hand-off contract with AI-RISK-001. Notable only, no risk. Triage SPL rebuilt on `Risk.All_Risk` |
