## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This risk aggregator raises a notable when an account receives risk from a privilege-change rule and AI-RBA risk whose activity happened at or after that privilege change, both within the same 24-hour risk window. Privilege-change rules cover an admin role or group grant, elevation, token manipulation, or exploitation for privilege escalation. Qualifying AI activity is execution, staging, collection, exfiltration or lateral movement. The order matters because an account that has just gained new privileges and then drives AI agents, uploads data to AI services or stages models is the pattern an insider or an attacker with a takeover leaves behind. The rule only reads `index=risk`. It creates one `threat` notable (severity high) per account per 24 hours and writes no risk itself (`action.risk = 0`).

### Prerequisites
- **ES risk index** (`index=risk`, data model `Risk.All_Risk` for the drilldowns). The rule needs two kinds of input in the same 24 hours:
  - **Privilege-change risk from non-AI rules.** A risk event counts when its `annotations.mitre_attack` (or a plain `mitre_attack` field) contains a technique from `_priv_techniques`, or when its `source` matches `_priv_rule_regex`. Typical sources are AD privileged-group changes, O365/Entra admin role grants, PIM activations, AWS IAM policy grants and UAC-bypass or token-manipulation endpoint rules. If a tenant has no such rule writing risk, this rule can never fire (Tenant C today).
  - **AI-RBA risk from the `hdsi_ai_*` packages.** Every AI-RBA rule writes `detection_id` (`hdsi_ai_<package>`) and `ai_kill_chain_phase` into its risk events, and the rule classifies AI events by those two fields. As a fallback for older content without `detection_id`, a source named `<Domain> - HDSI AI <Title> - Rule` is also accepted. An AI event without `ai_kill_chain_phase` is never counted, so the rule fails closed.
- **Common package:** `hdsi_ai_rba_common` (prerequisite of the AI-RBA rules that feed this one). The rule itself uses none of the common macros or lookups.
- The AI rules and the privilege rules can score the same person under different formats, such as `DOMAIN\jdoe`, `jdoe` and `jdoe@corp`. The rule joins them on `risk_entity`: the lower-cased `risk_object` with any `DOMAIN\` prefix and `@domain` suffix removed.

### How it works
- The rule reads `index=risk` for the dispatch window (`-24h@h` to `now`, hourly at :20), keeping only `risk_object_type` in `_object_types` (ships as `user`).
- It drops empty objects, `unknown`, `-`, `system` and anything matching `_nonhuman_regex` (NT SERVICE and NT AUTHORITY accounts, Entra service principals, GUIDs and `HOST$`).
- It classifies each event:
  - **AI signal:** an `hdsi_ai_*` detection whose `ai_kill_chain_phase` is in `_ai_phases` (execution, staging, collection, exfiltration, lateral_movement) and whose `detection_id` is not in `_ai_excluded_detections` (ships with `hdsi_ai_privileged_account_service_usage`). The `HDSI RBA AI` aggregators are never counted.
  - **Privilege signal:** a non-AI rule whose technique list matches `_priv_techniques` (T1068, T1134.x, T1484.x, T1548.x, T1611, T1098.002, T1098.003, T1098.007), or whose name matches `_priv_rule_regex`.
- It orders the two. An AI event counts only if its activity time is at or after the account's first privilege time. Risk event `_time` alone is not trusted for this, because a rule whose result has no `_time` writes its risk at search time, up to a day (daily rules) or a week (weekly rules) after the activity. Every risk event carries its search window (`info_min_time`, `info_max_time`), and the rule uses it to stay fail-closed:
  - **Privilege time** (earliest plausible change): the privilege rule's `firstTime` if it parses (epoch, `%m/%d/%Y %H:%M:%S`, `%Y-%m-%d %H:%M:%S`, ISO `%Y-%m-%dT%H:%M:%S`). Otherwise the result `_time` if it lies inside the rule's search window. Otherwise the end of that window (the latest the change can have happened).
  - **AI activity time**, used in this order:
    1. The AI rule's `lastTime` with a time of day, in the same formats.
    2. The result `_time`, when it lies inside the rule's search window (for example the hourly bucket written by the time-of-day anomaly rule).
    3. The start of the day for a date-only `lastTime` (`%Y-%m-%d`).
    4. The start of the AI rule's search window.
  - An AI event with none of these is never counted. A coarse time (3 or 4) is always a lower bound, so activity from before the privilege change is never counted as after it. The price is that coarse-timed rules can rarely qualify (see Limitations).
  - The notable shows which basis was used in `time_basis`.
- Per `risk_entity` it sums privilege and AI risk, lists the contributing rules, AI phases and matched techniques, and computes `gap_minutes` (first privilege time to first qualifying AI activity). Because the privilege time can come from the privilege rule's `firstTime`, `gap_minutes` can exceed 1,440 when a multi-day privilege rule wrote its risk inside the window.
- It fires when `priv_signals >= 1`, `ai_signals >= 1` and `ai_risk >= _min_ai_risk` (20). Suppression is 24 hours on `risk_entity`.
- Output fields for the notable are `risk_object`, `user`, `risk_entity`, `priv_detection_list`, `priv_technique_list`, `ai_detection_list`, `ai_detection_ids`, `ai_phase_list`, `priv_risk`, `ai_risk`, `total_risk`, `gap_minutes`, `time_basis`, `firstTime` (first privilege time) and `lastTime` (last AI activity). `mitre_attack` is T1098, T1134, T1548 and T1567, the same as the annotation.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_rba_ai_privilege_escalation_correlation_filter` | `()` | Exclusions inside the `index=risk` base search, e.g. `NOT source IN ("<routine PIM activation rule>")` or `NOT risk_object IN ("<break-glass account>")`. |
| `hdsi_rba_ai_privilege_escalation_correlation_object_types` | `"user"` | `risk_object_type` values that are correlated. Add `"system"` only if the privilege rules and the AI endpoint rules name hosts in the same format. |
| `hdsi_rba_ai_privilege_escalation_correlation_nonhuman_regex` | NT SERVICE / NT AUTHORITY / service principal / GUID / `$` | Objects that are never correlated. Add the tenant's service-account naming here. |
| `hdsi_rba_ai_privilege_escalation_correlation_priv_techniques` | T1068, T1134.x, T1484.x, T1548.x, T1611, T1098.002/.003/.007 | ATT&CK techniques that mark a privilege change. |
| `hdsi_rba_ai_privilege_escalation_correlation_priv_rule_regex` | privilege, escalat, elevat, admin group/role, role assign/grant, added to group, sudo, UAC, runas | Rule-name match for privilege rules with no usable annotation. |
| `hdsi_rba_ai_privilege_escalation_correlation_ai_phases` | execution, staging, collection, exfiltration, lateral_movement | AI-RBA phases that count as activity after the privilege change. |
| `hdsi_rba_ai_privilege_escalation_correlation_ai_excluded_detections` | `"hdsi_ai_privileged_account_service_usage"` | AI `detection_id` values never counted. Add general-use rules such as `hdsi_ai_after_hours_service_usage` if they are noisy for admins. |
| `hdsi_rba_ai_privilege_escalation_correlation_min_ai_risk` | `20` | Minimum summed AI risk after the privilege change. |
| `hdsi_rba_ai_privilege_escalation_correlation_customizations` | `search *` | Post-aggregation hook, e.g. `where total_risk>=80`. |

Several things are deliberately not privilege signals. T1078 (Valid Accounts), bare T1098 and the TA0004 tactic are excluded. In live data they tag tens of thousands of routine identity-provider MFA, new-IP and login events per week, and the previous version treated all of those as privilege escalation. Rules with bare T1098 that really do grant privileges, such as AD privileged-group changes, are caught by name instead.

### Threshold
The number of accounts that can fire is the daily pool of accounts with a privilege signal. Size it before enabling, and review which rules feed it. This search uses the same object filtering, identity key and classification as the rule:

```
index=risk risk_object_type IN (`hdsi_rba_ai_privilege_escalation_correlation_object_types`) `hdsi_rba_ai_privilege_escalation_correlation_filter`
| eval risk_entity=replace(mvindex(split(lower(trim(mvindex(risk_object,0))),urldecode("%5C")),-1),"@.*",""), rule_name=coalesce(mvindex(source,0),mvindex(search_name,0))
| where isnotnull(risk_entity) AND risk_entity!="" AND NOT in(risk_entity,"unknown","-","n/a","na","null","none","system","local system","nt authority") AND NOT match(lower(mvindex(risk_object,0)),`hdsi_rba_ai_privilege_escalation_correlation_nonhuman_regex`)
| where NOT match(rule_name,"HDSI RBA AI ") AND NOT match(coalesce(mvindex(detection_id,0),"-"),"^hdsi_ai_") AND NOT match(rule_name," - HDSI AI .+ - Rule")
| eval mitre_list=split(replace(upper(mvjoin(mvappend('annotations.mitre_attack',mitre_attack),",")),"[^A-Z0-9.,]",""),","), priv_tech=mvfilter(match(mitre_list,`hdsi_rba_ai_privilege_escalation_correlation_priv_techniques`))
| where mvcount(priv_tech)>0 OR match(rule_name,`hdsi_rba_ai_privilege_escalation_correlation_priv_rule_regex`)
| bin _time span=1d
| stats dc(risk_entity) as priv_accounts values(rule_name) as priv_rules by _time
```

Once the AI-RBA rules have run for a week, check the summed qualifying AI risk per account per day. Set `_min_ai_risk` near the median, and never below 20:

```
index=risk risk_object_type="user" detection_id="hdsi_ai_*" ai_kill_chain_phase IN (`hdsi_rba_ai_privilege_escalation_correlation_ai_phases`) NOT detection_id IN (`hdsi_rba_ai_privilege_escalation_correlation_ai_excluded_detections`)
| bin _time span=1d
| stats sum(risk_score) as ai_risk by _time risk_object
| stats perc50(ai_risk) as p50 perc90(ai_risk) as p90 by _time
```

### Known false positives / Limitations
- **Routine admin elevation followed by ordinary AI use.** Privileged Identity Management (PIM) role activations and admin-role grants are the largest privilege source in Tenant A: 12 to 14 accounts per week from each of those two rules. Several qualifying AI rules score general AI use rather than misuse of the new rights. Examples:
  - `hdsi_ai_privileged_account_service_usage` (collection) scores 30 for any AI-service visit by an admin, privileged-category or admin-named account. Alone it would meet `_min_ai_risk`, so "activate PIM, then open a chat assistant" would fire. It is excluded by default in `_ai_excluded_detections`.
  - `hdsi_ai_after_hours_service_usage` (exfiltration) scores AI use outside business hours.
  - The usage-anomaly rules (volume, time of day, peer group).
  
  An administrator who activates a role and then uses an AI coding agent, or uses AI services after hours, will still fire. When admins are expected to use AI tooling, exclude the PIM rule or the admin accounts in `_filter`, or add the general-use rules to `_ai_excluded_detections`.
- **Broad rule names.** The name regex also matches rules that are about privileged *accounts*, not privilege *changes*, for example "Multiple Privileged Account Passwords Changed" (seen in Tenant D) and third-party rules about privileged-account logons. Exclude them in `_filter` if they are noisy.
- **Non-human objects.** Some privilege rules score role groups, service principals and AWS IAM service users as `user`. Seen live: an Exchange role-group name, an Entra service principal, IAM upload users and an `NT SERVICE\` account. The AI-RBA rules do not score these objects, so they rarely correlate, and `_nonhuman_regex` removes the common forms.
- **Mis-annotated rules.** In Tenant A, one web-attack rule carries T1134.004 and writes risk on about 960 systems a week. It is ignored only because `system` is not correlated by default. Exclude such rules in `_filter` before adding `system`.
- **Coarse-timed AI rules rarely qualify.** Ordering is fail-closed, so an AI rule without an exact activity time is placed at the earliest moment its activity can have happened. In the current AI-RBA set this applies to:
  - `hdsi_ai_gradual_data_exfiltration_via_ai` (weekly, date-only `lastTime`).
  - The daily rules that write a date-only `lastTime`.
  - `hdsi_ai_usage_volume_anomaly` and `hdsi_ai_user_peer_group_usage_anomaly` (daily, no `lastTime`).
  
  Their lower bound is the start of the reported day or of the search window, and that is usually before any privilege change inside this rule's 24-hour window. As a result they almost never count. This is deliberate: counting them by risk `_time` reported activity from up to 7 days earlier as "after" the privilege change. Rules that emit a time-of-day `lastTime` (all hourly and 15-minute AI rules, and most daily ones) or keep an hourly result `_time` (`hdsi_ai_time_of_day_usage_pattern_anomaly`) are ordered precisely.
- **Late privilege timing.** When a privilege rule writes no parseable `firstTime` and its result has no `_time`, its time is the end of that rule's search window. That is up to the length of the window (an hour for hourly rules, a day for daily aggregate rules such as an "increase in privilege escalations" rule) after the real change. AI activity in that gap is not counted. Privilege rules that emit `firstTime` are timed from it.
- **Account matching.** The `risk_entity` key removes the domain, so `jdoe@a.example` and `jdoe@b.example` merge. This is acceptable in single-directory tenants. In a multi-forest tenant, review it before enabling.

### Validation
Read-only live tests ran on 2026-10-09 against 4 production ES tenants. No `hdsi_ai_*` rule is deployed in any tenant, so there are no AI risk events. The logic was proven with synthetic risk events and with real privilege events plus synthetic AI follow-ups.

| Tenant | Privilege-change risk (7d) | Parse (search + 2 drilldowns) | Scheduled window (-24h@h) | 7-day window | Real privilege events (7d) + one synthetic AI follow-up per account |
|---|---|---|---|---|---|
| A | 9 rules, 2 to 16 accounts/day | OK | 0 rows, 8.8 s | 0 rows, 7.6 s | 50 notables, about 7 a day. This is the ceiling if every privileged account used AI afterwards. A service-principal object was correctly dropped. |
| B | 1 rule (IAM grant), 0 to 2 accounts/day | OK | 0 rows, 2.9 s | 0 rows, 4.6 s | 6 notables (IAM service users) |
| C | none | OK | 0 rows, 3.5 s | 0 rows, 2.8 s | 0 (no privilege source) |
| D | 7 rules, 0 to 7 accounts/day | OK | 0 rows, 1.4 s | 0 rows, 2.4 s | 14 notables. An `NT SERVICE\` object was correctly dropped. |

How real privilege events are timed (7 days, by the rule's own classification):
- **Tenant A:** 23 events (13 accounts) by `firstTime`, 3 by result `_time`, 37 by search-window end.
- **Tenant B:** all 7 by search-window end.
- **Tenant D:** 8 by result `_time`, 19 by search-window end.

The README Threshold search reproduces the rule's pool: Tenant A 2 to 15 accounts/day, B 1 to 2, C none, D 2 to 6.

The synthetic test fed 34 risk events through the full pipeline and produced exactly the 5 expected notables:
- A privilege change in `DOMAIN\user` format followed by AI exfiltration in UPN format.
- A name-matched AD privileged-group change followed by AI execution, timed from a ctime `lastTime`.
- T1068 in a plain `mitre_attack` field followed by two AI events summing to 25.
- T1134.001 followed by an AI rule identified by name only.
- A PIM activation followed by AI lateral movement.

It correctly suppressed these cases:
- AI activity before the privilege change.
- A daily AI risk event whose `lastTime` was earlier than the privilege change.
- Recon-only AI events.
- T1078-only "privilege".
- An AI risk sum of 10 (below the minimum).
- AI-only privileged-account usage.
- `unknown`, `HOST$`, `NT SERVICE\` and service-principal objects.
- A `HDSI RBA AI` aggregator event.
- A `system` object.

With `"system"` added to `_object_types`, the system case produced the expected sixth notable.

A second synthetic test (22 risk events, Tenant D) checked the time ordering. It gave exactly the 5 expected notables:
- AI execution with a ctime `lastTime` after the privilege change.
- An hourly result `_time` from the time-of-day anomaly rule.
- A privilege rule timed from its `firstTime` 10 hours earlier, gap 300 minutes.
- An ISO `lastTime`.
- An epoch `lastTime` across `DOMAIN\user` and UPN formats.

It suppressed these cases:
- A weekly gradual-exfiltration event with a date-only `lastTime` 4 days old, written 1 hour ago.
- A daily volume-anomaly event with no `lastTime`, written 1 hour ago.
- A ctime `lastTime` 1 day old.
- AI activity before a privilege rule's window end.
- `hdsi_ai_privileged_account_service_usage`.
- An AI event with no time information at all.

The first two cases fired in the previous version.

Before this version, the rule could never fire. Its AI test `match(search_name,"^HDSI AI ")` never matches real names such as `Network - HDSI AI ... - Rule`. Its privilege test also counted T1078 and any rule name containing "Admin", which would have treated about 85,000 identity-provider MFA events a week in Tenant A as privilege escalation.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:
- Enable the `hdsi_ai_*` risk rules and confirm their risk events carry `detection_id` and `ai_kill_chain_phase`.
- Confirm that at least one privilege-change rule writes user risk.
- Size the privilege pool with the Threshold search.
- Decide how routine PIM and admin-role activity is handled.

This rule is notable-only (`action.notable = 1`, `action.risk = 0`) and adds no risk to the risk index. Enabling it is a separately approved change.
