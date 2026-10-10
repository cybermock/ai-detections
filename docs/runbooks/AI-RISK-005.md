# AI-RISK-005 - HDSI RBA AI Multi-Vector Risk

> **Detection ID:** AI-RISK-005
> **Package:** `hdsi_rba_ai_multi_vector_risk` (v1.1.0, `deployment_type: global`)
> **Correlation search:** `Threat - HDSI RBA AI Multi-Vector Risk - Rule`
> **Status:** Active (ships with `enable_alerting: false`; enabling is a separately approved change)
> **Type:** Risk aggregator. Creates a notable (`action.notable = 1`), writes **no** risk (`action.risk = 0`)
> **Notable:** severity `high`, security domain `threat`, title `HDSI AI Multi-Vector Risk for <type> <object> (<n> vectors)`
> **Risk Score:** N/A (notable only)
> **MITRE ATT&CK:** T1588.007 Obtain Capabilities: Artificial Intelligence (Resource Development). Contributing techniques are listed per notable in `contributing_mitre`
> **Data Source:** ES risk index (`index=risk`); drilldowns use the `Risk.All_Risk` data model
> **Schedule:** `6-59/15 * * * *` (every 15 minutes, offset 6)
> **Lookback Window:** `-24h` to `now`, with a rising-edge window of `-65m` on index time
> **Suppression:** 24 hours (`86400s`) per `risk_object_key,risk_object_type,vector_count`
> **Kill Chain Phase:** N/A (aggregation across phases)
> **Last Updated:** 2026-10-09

---

## Overview

This rule raises a notable when one person, or one host with no attributed user, collects HDSI AI risk across several **different kinds** of AI behaviour in 24 hours. It needs at least 3 of 6 risk vectors, and at least one of them must be high impact: data exposure, risky access or adversarial AI.

Heavy but ordinary AI use does not fire it. Browsing unsanctioned AI sites (shadow usage), unusual usage volume (usage anomaly) and running AI desktop apps, CLIs or coding agents (local tooling) are all normal-impact vectors. A developer running Claude Code, Codex or a Copilot agent through builds, package installs, `git push` and `curl` stays below the bar. What fires is breadth **plus** something that matters: the same person also uploading data, reaching AI from an unmanaged device or evasion path, or showing adversarial indicators.

The rule fires on a rising edge: when an object first reaches the threshold, or adds a new vector, not on every run while it stays above it. Hosts attributed to exactly one user are folded into that user, so host-only evidence (DNS, local LLM ports) counts toward the person.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique ID | T1588.007 (annotation and `mitre_attack` result field) |
| Technique Name | Obtain Capabilities: Artificial Intelligence |
| Tactic | Resource Development |
| Sub-technique | T1588.007. Techniques of the contributing rules are in `contributing_mitre` |

---

## Detection Logic

### Plain English

1. Read 24 hours of `index=risk` where `source` matches `* - HDSI AI * - Rule` and `risk_object_type` is `user` or `system`. Machine accounts (`*$`) and events tagged `risk_suppression` are excluded, then the tenant filter macro is applied. Aggregator output (`HDSI RBA AI`) never matches the pattern.
2. Drop placeholder objects (empty, `unknown`, `-`, `n/a`, `na`, `none`, `null`, `undefined`) and user objects that are built-in OS accounts (`root`, `system`, `nt authority\system`, `local service`, `network service`). Objects are keyed in lower case (`risk_object_key`).
3. Work out `detection_key`: the `detection_id` the rule wrote, or, if missing, the package id derived from the stanza name.
4. Map each detection to a vector with `hdsi_rba_ai_multi_vector_risk_vector_map` (table below). Health checks and the hunting-only API discovery search map to nothing.
5. Fold hosts into users: a `system` object whose events all name the same single `user`, where that user also has user-type HDSI AI risk, is merged into the user (`related_systems`). Shared hosts (two or more users) stay separate.
6. Aggregate per object: distinct vectors, high-impact vectors, detections, risk events (a user+host pair from one result counts once), total risk, and contributing MITRE.
7. Fire when `vector_count >= 3`, `high_impact_count >= 1` and at least one vector was first indexed in the last 65 minutes.

| Vector | Impact | Detections |
|---|---|---|
| `shadow_usage` | normal | Unsanctioned Web Access, First Seen Provider For User, Repeated Unsanctioned Access Burst, Multiple Services In Single Session, New Provider Adoption Velocity, DNS Queries To AI Domains, API Access From Non-Dev Endpoint, Code Assistant Network Connection |
| `usage_anomaly` | normal | After Hours Service Usage, Time-of-Day Usage Pattern Anomaly, Usage Volume Anomaly, User Peer Group Usage Anomaly |
| `local_tooling` | normal | Unsanctioned CLI Execution, Unsanctioned Desktop App Execution, Scripted CLI Invocation, Local LLM Framework Execution, Local LLM Listening Port Detected, Agent Framework Execution, MCP Server Execution, LLM Model File Download, Browser Extension Activity, Agent Autonomous Action (routine and development `agent_activity` events) |
| `risky_access` | **high** | Access Via VPN/Proxy Evasion, Access From Unmanaged Device, Usage From Personal Account / OAuth Mismatch, Privileged Account Service Usage |
| `data_exposure` | **high** | High Volume Upload, DLP Violation On Service Upload, Sanctioned DLP Violation, Personal Email To AI Upload, Gradual Data Exfiltration, Copy-Paste Correlation, Usage Following Data Access Spike, Browser Extension High-Volume Data Transmission, Suspicious Model File Exfiltration, API Key Exposure In Code/DLP |
| `adversarial` | **high** | Prompt Injection Indicators, Generated Phishing Indicators, Deepfake Tool Execution/Access, Voice Cloning API Access, Compromised Plugin/Extension Installation, Assisted Lateral Movement, Agent Autonomous Action (high-signal events only: `risk_category` credential_access, persistence or system_change) |

Access From Unmanaged Device, Usage From Personal Account / OAuth Mismatch, DLP Violation On Service Upload and Browser Extension High-Volume Data Transmission are incubating (not released; see `saved_searches/incubating/`). The vector map keeps them so they count once promoted; until then they contribute nothing.

### Key Fields

| Field | Description | Example Value |
|---|---|---|
| `risk_object` / `risk_object_type` | The user (or unattributed system) that reached the threshold | `jdoe@corp.example` / `user` |
| `risk_object_key` | Lower-case key used for suppression | `jdoe@corp.example` |
| `vector_count` / `vector_list` | Distinct vectors reached | `3` / `data_exposure, local_tooling, shadow_usage` |
| `high_impact_list` | High-impact vectors reached | `data_exposure` |
| `new_vector_list` | Vectors first indexed in the rising-edge window (why it fired now) | `data_exposure` |
| `vector_detections` | `vector: detection` pairs | `local_tooling: Unsanctioned CLI Execution` |
| `detection_count` / `risk_event_count` / `total_risk` / `max_risk_score` | Contribution counts; each result counted once even when it scored a user and a host | `4` / `7` / `85` / `40` |
| `related_systems` / `related_system_list` | Hosts merged into this user | `wks-0142` |
| `attributed_users` | For unmerged systems: the single user seen on them, if any | `jdoe` |
| `contributing_objects` | Quoted, comma-separated list of the user key and merged hosts, used by the drilldowns | `"jdoe@corp.example","wks-0142"` |
| `contributing_mitre` | Techniques of the contributing rules | `T1567`, `T1588.007` |

### Thresholds

| Parameter | Default Value | Macro | Notes |
|---|---|---|---|
| Distinct vectors | `3` | `hdsi_rba_ai_multi_vector_risk_min_vectors` | Replaces the old `multi_vector_categories` row of `ai_detection_config` (no longer read) |
| High-impact vectors | `1` | `hdsi_rba_ai_multi_vector_risk_min_high_impact` | `0` alerts on breadth alone (not recommended) |
| High-impact set | `^(data_exposure\|risky_access\|adversarial)$` | `hdsi_rba_ai_multi_vector_risk_high_impact_vectors` | Regex |
| Rising-edge window | `-65m` | `hdsi_rba_ai_multi_vector_risk_new_vector_window` | Covers four 15-minute runs. `-24h` = level-triggered |

---

## Triage Steps

> **Estimated triage time:** 20-30 minutes

Use the notable fields directly. `$contributing_objects$` is the notable's `contributing_objects` value, pasted as written (it is already quoted and comma separated, with backslashes doubled).

The `tstats summariesonly=t` evidence searches read accelerated summaries only. In validation the most recent 15-30 minutes were not yet summarised on two tenants, so for very recent activity re-run them later, or with `summariesonly=f` over a short window.

### Step 1: Validate the notable

```spl
index=notable source="Threat - HDSI RBA AI Multi-Vector Risk - Rule" earliest=-7d
| search risk_object_key="$risk_object_key$"
| table _time, risk_object, risk_object_type, vector_count, vector_list, high_impact_list, new_vector_list, detection_count, risk_event_count, total_risk, related_system_list, attributed_users
```

- Confirm the object is a real person or host, not a service, kiosk or shared account.
- Several notables for the same object in one day with rising `vector_count` mean it is adding vectors: escalate.
- `new_vector_list` is what changed. Start there.

### Step 2: Break the risk down by vector

```spl
| from datamodel:"Risk.All_Risk"
| search source="* - HDSI AI * - Rule" risk_object_type IN ("user", "system") risk_object IN ($contributing_objects$)
| eval detection_label=replace(replace(source, "^[^-]+ - HDSI AI ", ""), " - Rule$", "")
| eval detection_key=if(match(mvindex(detection_id, 0), "^hdsi_ai_[a-z0-9_]+$"), mvindex(detection_id, 0), "hdsi_ai_".trim(replace(lower(detection_label), "[^a-z0-9]+", "_"), "_"))
| `hdsi_rba_ai_multi_vector_risk_vector_map`
| eval impact=if(match(ai_vector, `hdsi_rba_ai_multi_vector_risk_high_impact_vectors`), "high", "normal")
| stats count as risk_events sum(risk_score) as risk values(detection_label) as detections values(risk_object) as objects min(_time) as firstTime max(_time) as lastTime by impact ai_vector
| convert ctime(firstTime) ctime(lastTime)
| sort impact - risk
```

- The high-impact row decides the case. Open that contributor's own runbook (see Related Detections) and triage it first.
- Normal-impact rows give context: which providers, which tools, from which hosts.

### Step 3: Read the contributing risk events

This is the first drilldown (`View contributing AI risk events`).

```spl
| from datamodel:"Risk.All_Risk"
| search source="* - HDSI AI * - Rule" risk_object_type IN ("user", "system") risk_object IN ($contributing_objects$)
| table _time, source, risk_object, risk_object_type, risk_score, ai_kill_chain_phase, risk_category, provider, risk_message
| sort - _time
```

- For Agent Autonomous Action events, `risk_category` tells you whether the event counted as adversarial (`credential_access`, `persistence`, `system_change`) or as local tooling.
- Check whether the high-impact event and the normal events come from the same host and provider. A single coherent session is more concerning than three unrelated events.

### Step 4: Review the raw AI web or DNS activity

For a user (Web/SSE data). The `fillnull_value` keeps SSE rows where only `site` (app name) is mapped:

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

`$account$` is the bare account name (the risk object without `DOMAIN\` or `@domain`).

For a host, DNS is the most portable signal (trailing dots in queries are handled by `ai_domains_filter`):

```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.src="$src$" by DNS.src DNS.query
| rename DNS.* as *
| eval ai_domain=query, ai_input_type="dns"
| `ai_domains_filter`
| stats sum(count) as queries values(ai_domain) as domains min(firstTime) as firstTime max(lastTime) as lastTime by src provider
| convert ctime(firstTime) ctime(lastTime)
| sort - queries
```

### Step 5: Identify the user or host

```spl
| inputlookup identity_lookup_expanded
| search identity="$account$"
| table identity, first, last, email, managedBy, bunit, category, priority, watchlist
```

```spl
| inputlookup asset_lookup_by_str
| search asset="$src$"
| table asset, ip, dns, nt_host, owner, bunit, category, priority, is_expected
```

- Developers, data scientists and AI champions reach `shadow_usage` and `local_tooling` routinely. Focus on the high-impact vector.
- A host with `attributed_users` empty and a server category (build host, jump box) needs the asset owner, not the user's manager.

### Step 6: Determine sanctioned status

```spl
| inputlookup ai_sanctioned_entities
| search entity="*$account$*" OR entity="*$src$*" OR entity="*"
| table entity_type, entity, provider, scope, expires, owner, reason, enabled, allow_key
```

### Step 7: Make a determination

- **True Positive:** the high-impact vector is real misuse (data sent to an unsanctioned provider, AI reached from an evasion path, an agent reading credentials it should not, phishing or deepfake tooling), and the breadth supports a deliberate pattern.
- **Benign True Positive:** an approved AI engineering user whose high-impact event is expected (for example a coding agent reading a project `.env` file).
- **False Positive:** two people merged under one object, or a shared host attributed to one user by mistake.

---

## True Positive Indicators

- The high-impact vector is `data_exposure` together with an unsanctioned provider in `shadow_usage`.
- `risky_access` from an unmanaged device or VPN/proxy evasion alongside local tooling on a corporate host: the user is working around controls.
- `adversarial` from Agent Autonomous Action with `credential_access` on a host where the user is not a developer.
- `new_vector_list` keeps growing over the day (several notables with rising `vector_count`).
- The user also has a Data Collection Kill Chain (AI-RISK-003) or Privilege Escalation (AI-RISK-004) notable.

---

## False Positive Scenarios

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Developer or AI champion: CLI + code assistant + agent work, plus one high-signal agent event such as a routine `.env` read | Medium | Exclude the AI engineering group in `..._filter` (by `risk_object`) or `..._customizations`, or remap the agent rule's `credential_access` events to `local_tooling` in the vector map |
| Privileged admin who uses AI (Privileged Account Service Usage is `risky_access`) | Medium | Sanction the admin's AI use, or remap that detection in the vector map |
| Identity split (UPN vs `DOMAIN\sam`) lowering breadth, or two people merged by a shared name | Low | Normalise identities in the contributing rules; review `related_systems` and `attributed_users` |
| Host keyed by IP in DNS rules and by hostname in endpoint rules, so a laptop appears as two objects | Low (missed merge, not a false alert) | Normalise `src` to a hostname with ES asset correlation in the contributing rules |
| Rising edge at deployment: an object already above the threshold is not reported | N/A | Run once with `..._new_vector_window` set to `"-24h"` |

---

## Response Actions

### If confirmed True Positive

1. **Contain:** act on the high-impact vector first: block the provider or the evasion path, disable the personal OAuth grant, or stop the agent process and revoke the credentials it read.
2. **Notify:** the user's manager and data governance; security engineering if an AI agent or plugin was involved.
3. **Investigate:** triage each high-impact contributor with its own runbook, and check for AI-RISK-003 and AI-RISK-004 notables on the same user.
4. **Remediate:** enforce sanctioned AI tooling, rotate exposed secrets, remove unapproved extensions or local model runtimes.
5. **Document:** record the vector breakdown from Step 2 in the case.

### If Benign True Positive

1. Add the user, group or provider to `ai_sanctioned_entities` with a scope and `expires` date, so the contributors stop scoring.
2. For an AI engineering population, add a `..._filter` exclusion and document it.
3. Close the notable as Benign True Positive.

---

## Tuning Guidance

### Reducing false positives

- Sanction approved AI use at the source (`ai_sanctioned_entities`).
- Use `hdsi_rba_ai_multi_vector_risk_filter` for object exclusions (risk event field names), or `risk_object_type="user"` to alert on users only.
- Move a detection to a different vector, or to `null()`, in `hdsi_rba_ai_multi_vector_risk_vector_map`.
- Add tenant service accounts to `hdsi_rba_ai_multi_vector_risk_builtin_accounts` so they never act as a user or attribute a host.
- Raise `..._min_vectors` to 4 if most 3-vector notables are benign power users.

### Adjusting thresholds

After the contributors have written risk for 14 days, use the Threshold SPL in the package README (`saved_searches/packages/hdsi_rba_ai_multi_vector_risk/README.md`). It applies the rule's exclusions, detection keys, vector map and host-to-user merge per day and reports `would_fire_3` and `would_fire_4`. A quick view of breadth by object:

```spl
| from datamodel:"Risk.All_Risk"
| search source="* - HDSI AI * - Rule" risk_object_type IN ("user", "system") NOT risk_object IN ("*$", "unknown", "-")
| eval detection_label=replace(replace(source, "^[^-]+ - HDSI AI ", ""), " - Rule$", "")
| eval detection_key=if(match(mvindex(detection_id, 0), "^hdsi_ai_[a-z0-9_]+$"), mvindex(detection_id, 0), "hdsi_ai_".trim(replace(lower(detection_label), "[^a-z0-9]+", "_"), "_"))
| `hdsi_rba_ai_multi_vector_risk_vector_map`
| where isnotnull(ai_vector)
| eval hi=if(match(ai_vector, `hdsi_rba_ai_multi_vector_risk_high_impact_vectors`), ai_vector, null())
| stats dc(ai_vector) as vectors dc(hi) as high_impact by risk_object risk_object_type
| stats count as objects count(eval(vectors>=3)) as breadth_3 count(eval(vectors>=3 AND high_impact>=1)) as would_fire_3 count(eval(vectors>=4 AND high_impact>=1)) as would_fire_4 by risk_object_type
```

Run it over 24 hours (time picker). It does not merge hosts into users, so it slightly under-counts users.

### Adding allowlist entries

```
entity_type,entity,provider,scope,expires,owner,reason,enabled,allow_key
user,<username>,<provider>,provider,<YYYY-MM-DD>,<your_name>,<justification>,1,<username>|<provider_lowercase>
```

---

## Related Detections

| Detection ID | Name | Relationship |
|---|---|---|
| AI-022, AI-023, AI-026, AI-016 | Access Via VPN/Proxy Evasion; Access From Unmanaged Device; Personal Account / OAuth Mismatch; Privileged Account Service Usage (AI-023 and AI-026 are incubating: not released) | `risky_access` (high impact) |
| AI-007, AI-020, AI-038, AI-027, AI-044, AI-025, AI-043, AI-024, AI-032, AI-033 | Upload, DLP, email, gradual exfiltration, copy-paste, data-access spike, extension transmission, model exfiltration, API key exposure (AI-020 and AI-024 are incubating: not released) | `data_exposure` (high impact) |
| AI-030, AI-031, AI-034, AI-045, AI-036, AI-035, AI-039 | Prompt injection, AI phishing, deepfake, voice cloning, compromised plugin, lateral movement, agent autonomous action (high-signal) | `adversarial` (high impact) |
| AI-001-002-003, AI-028, AI-009, AI-010, AI-018, AI-042, AI-012, AI-006, AI-019 | Unsanctioned web access, first-seen provider, burst, multiple services, adoption velocity, DNS, non-dev API access, code assistant | `shadow_usage` |
| AI-015, AI-041, AI-017, AI-040 | After hours, time-of-day, volume, peer group | `usage_anomaly` |
| AI-004, AI-005, AI-008, AI-011, AI-014, AI-037, AI-046, AI-013, AI-021, AI-039 | CLI, desktop app, scripted CLI, local LLM, listening port, agent framework, MCP server, model download, browser extension, agent routine activity | `local_tooling` |
| AI-RISK-003 | HDSI RBA AI Data Collection Kill Chain | Ordered collection-to-upload sequence |
| AI-RISK-001 / AI-RISK-002 | HDSI RBA AI User Risk Threshold Exceeded (medium / critical) | Score-based view of the same risk |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Model | ES risk index (`index=risk`); `Risk.All_Risk` for drilldowns |
| Required Fields | `source`, `risk_object`, `risk_object_type`, `risk_score` (`calculated_risk_score` when set), `risk_message`, `tag`, `_indextime`; result fields `detection_id`, `ai_kill_chain_phase`, `risk_category`, `risk_tier`, `user`, `annotations.mitre_attack` / `mitre_attack` |
| Contributors | At least three HDSI AI detections from different vectors writing risk. With DNS and endpoint data only, five of six vectors are reachable; `usage_anomaly` needs Web or Network_Traffic data |
| Sourcetype Examples | N/A (reads risk events) |
| CIM Compliance | Contributors must keep their shipped stanza names (`* - HDSI AI * - Rule`); a renamed copy is not counted |
| Acceleration | Not required for the rule. Triage Step 4 uses `tstats summariesonly=t` on Web and Network_Resolution |
| Lookups | None at run time. Triage uses `identity_lookup_expanded`, `asset_lookup_by_str`, `ai_sanctioned_entities`, `ai_provider_domains` |
| Prerequisite package | `hdsi_ai_rba_common` (required by every contributor) |

### Validation (2026-10-09)

Read-only runs against 4 production ES tenants (Tenant A-D). No HDSI AI detection was deployed, so real runs returned 0 rows.

| Tenant | Parses (search + 3 drilldowns) | Rows 24 h | Notes |
|---|---|---|---|
| A | OK | 0 (about 3 s) | System risk keyed mostly on IPv4. A harmless warning about a deactivated event type appears because `NOT tag="risk_suppression"` evaluates event types |
| B | OK | 0 (about 2 s) | System risk keyed mostly on IPv4 |
| C | OK | 0 (about 3 s) | 95% of system risk events carry `user`, so host-to-user merging applies |
| D | OK | 0 (under 1 s) | Warns that the `risk_suppression` tag does not exist; harmless |

A 45-event synthetic test fired the 6 expected notables (including a merged laptop with `total_risk` 75 instead of a double-counted 140, a `DOMAIN\user` identity, and a `root`-only build host that stayed a system object) and suppressed the developer-only, aged-out, built-in-account, machine-account and normal-impact-only cases.

---

## Revision History

| Date | Author | Change |
|---|---|---|
| 2026-03-04 | Hurricane Labs | Initial runbook |
| 2026-10-09 | Hurricane Labs | 1.1.0: rewritten for the released package. Stanza renamed to `Threat - HDSI RBA AI Multi-Vector Risk - Rule`. Six explicit vectors with a high-impact requirement, agent `risk_category` mapping, host-to-user merge, paired-score counting, placeholder and built-in account exclusion, rising-edge firing, 24 h suppression on `risk_object_key,risk_object_type,vector_count`, MITRE T1588.007. `multi_vector_categories` replaced by package macros. Notable only, no risk. Triage SPL rebuilt on `Risk.All_Risk`, with `url_domain`/`site` handling |
