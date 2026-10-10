## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This is the medium-severity risk incident rule for the HDSI AI detection set. It reads the user risk that the HDSI AI detections write to the ES risk index and totals it per person over a rolling 24 hours. It raises one notable when two conditions hold:
- At least two distinct AI detections contributed.
- The total is in the medium band: by default 60 up to, but not including, 90.

Users at or above the high threshold go to `hdsi_rba_ai_user_critical_risk_threshold_exceeded` instead. So do users who already received a critical notable in the last 24 hours. As a result, one total never produces both notables.

Each notable lists the contributing detections with their points, the top contributor's share of the total, and the AI kill-chain phases and MITRE techniques seen. The rule writes no risk (`action.risk = 0`). MITRE ATT&CK annotation: T1588.007 (Obtain Capabilities: Artificial Intelligence), the common theme of the contributing detections. The techniques actually observed are listed per notable in `contributing_mitre_attack`.

### Prerequisites
- **ES risk index.** The rule reads raw risk events from `index=risk`, set by the `_risk_index` macro. The drilldowns use `| from datamodel:"Risk.All_Risk"`. Both are standard in ES 7 and 8.
- **HDSI AI detections writing user risk.** Without them the rule returns nothing. A risk event counts when either of these holds:
  - Its `source` matches `* - HDSI AI * - Rule` (the shipped stanza names).
  - Its `detection_id` starts with `hdsi_ai_`. Every HDSI AI detection writes `detection_id`, and ES copies result fields into the risk event (verified on all four tenants).

  The `hdsi_ai_health_*` checks write no risk and are excluded anyway. Host-only detections never contribute: DNS Queries To AI Domains, Access From Unmanaged Device and Local LLM Listening Port Detected. Neither do the system-only rows of the other detections.
- **Common package `hdsi_ai_rba_common`.** The rule reads the `medium_risk_threshold` and `high_risk_threshold` rows of `ai_detection_config`. If a row is missing, it uses 60 and 90.
- **Notable index.** The rule reads `index=notable` to skip users who already have a critical notable.
- **Companion rule.** Deploy it with `hdsi_rba_ai_user_critical_risk_threshold_exceeded`. The two are designed as one banded pair.

### How it works
- **Base search:** user risk events from HDSI AI detections, health checks excluded. `risk_object` must be set and must not be `unknown`, `-` or end in `$`. The tenant `_filter` macro is applied inline here.
- **Person key (`_user_key`):** `user_key` is the lowercased `risk_object` with any `@domain` suffix and `DOMAIN\` prefix removed. So `jdoe@example.com`, `EXAMPLE\jdoe` and `jdoe` add up as one person, because web and SSE detections score the UPN while endpoint detections score the account name. Built-in local accounts (administrator, admin, guest, defaultaccount, wdagutilityaccount) keep their qualifier, written `HOST/administrator`, so they never merge across the fleet.
- **Excluded accounts (`_excluded_accounts`):** the following are never totalled:
  - placeholders: `none`, `null`, `n/a`, `(null)`, `undefined`, masks;
  - `$` computer accounts;
  - OS service identities: SYSTEM, LOCAL/NETWORK SERVICE, `NT AUTHORITY\*`, `NT SERVICE\*`, `IIS APPPOOL\*`, DWM-n, UMFD-n;
  - shared Unix accounts: root, nobody, daemon;
  - built-in accounts with no host or domain qualifier: a bare `administrator`, `admin` or `guest`.
- **Per detection:** risk is summed per `user_key` and `detection_key`. `detection_key` is the `detection_id`, or `source` when the event has none. A cloned rule that keeps the same `detection_id` counts as the same detection.
- **Per person:**
  - `total_risk`: sum of the `risk_score` each detection wrote.
  - `distinct_detections`: the number of different `detection_key` values.
  - `risk_event_count`: the number of risk events.
  - `detection_breakdown`: each detection with its points, largest first. `detection_list` keeps the top 8.
  - `top_detection` and `top_detection_share`: the largest contributor and its percentage of the total.
  - `kill_chain_phases`: from the detections' `ai_kill_chain_phase`.
  - `contributing_mitre_attack`.
  - `user`: the `risk_object` spelling that carries the most risk.
  - `account`.
  - `firstTime` and `lastTime`.
- **Band:** a row is kept when `total_risk >= medium_risk_threshold`, `total_risk < high_risk_threshold` and `distinct_detections >= min_detections`.
- **Hand-off guard:** rows whose `user_key` has a notable from the critical rule in the last 24 hours are dropped. This uses a left `join` on `index=notable`, and the rule name comes from the `_critical_rule` macro. Without it, a total that fell back from 92 to 88 as old events aged out would raise a medium notable after the critical one.
- **Coherence with the critical rule:** both rules use the same index, membership filters, person key, account exclusions, threshold rows and `-24h@m` window. A person is therefore in exactly one band at a time. The person-key and excluded-account macros here are copies of the critical rule's macros and must be kept identical to them.
- **Schedule:** every 15 minutes (`0-59/15`), over `-24h@m` to `now`. Suppression is 24 h on `user_key`, so a user who stays in the medium band all day gets one notable. Escalation to the critical band is raised by the critical rule.
- **Notable:** severity medium, security domain threat. There are three drilldowns: the contributing AI risk events, the AI risk summarised by detection, and all risk (any content) for the person. Each drilldown applies the same person key to the `Risk.All_Risk` data model.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_rba_ai_user_risk_threshold_exceeded_filter` | `()` | Exclusions inline in the base search, using risk event field names. For example `NOT risk_object IN ("svc_*")`, or `NOT source="Network - HDSI AI Unsanctioned Web Access - Rule"` to stop one detection counting. **Apply the same exclusion to the critical rule's filter.** Otherwise the two rules total different events and their bands can overlap. |
| `hdsi_rba_ai_user_risk_threshold_exceeded_min_detections` | `2` | Minimum distinct HDSI AI detections behind a medium total. With 2, a single detection, whether it fires repeatedly or once with a high score, cannot raise this notable on its own. Its risk is still on the user, and totals at 90 or more still go to the critical rule, which ships with 1. Set this to 1 to alert on the medium total alone. |
| `hdsi_rba_ai_user_risk_threshold_exceeded_user_key` | key eval | Person key. Must stay identical to `hdsi_rba_ai_user_critical_risk_threshold_exceeded_user_key`. Switch both to `eval user_key=lower(trim(risk_object))` if separate email domains or forests reuse account names for different people. |
| `hdsi_rba_ai_user_risk_threshold_exceeded_excluded_accounts` | boolean | Accounts that are never one person. Must stay identical to the critical rule's copy. Remove `root` from both if root logins are individually attributable. |
| `hdsi_rba_ai_user_risk_threshold_exceeded_risk_index` | `index=risk` | Where risk events are written. Must stay identical to the critical rule's copy. |
| `hdsi_rba_ai_user_risk_threshold_exceeded_critical_rule` | the critical rule's stanza name | The source used by the hand-off guard. Change it only if the critical rule is renamed. |
| `hdsi_rba_ai_user_risk_threshold_exceeded_customizations` | `search *` | Post-band hook. Fields: `user_key`, `user`, `account`, `risk_object_values`, `total_risk`, `distinct_detections`, `risk_event_count`, `detections`, `detection_breakdown`, `top_detection`, `top_detection_share`, `kill_chain_phases`, `contributing_mitre_attack`. For example, `where top_detection_share<90` drops totals that one detection dominates. |

The band limits are not macros. They are the `medium_risk_threshold` and `high_risk_threshold` rows of `ai_detection_config` in the common package. The critical rule reads the same `high_risk_threshold` row, so the medium band always ends where the critical band starts. Change those rows in the common package lookup, never in a copy of this search.

### Threshold
The defaults (60 and 90) are starting values. They could not be measured on AI risk, because no tenant had HDSI AI risk when this version was validated. Two to four weeks after the HDSI AI detections are enabled, profile daily per-person totals with the rule's own filters:

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

A reasonable tenant setting puts `medium_risk_threshold` near p95, but not below 40. Put `high_risk_threshold` near p99, at least 30 points above medium. To estimate notables per day before applying a value, count the person-days at or above the new medium value and divide by 14.

### Known false positives / Limitations
- **Heavy users of approved AI tools.** Several web detections score the same everyday use from different angles: Unsanctioned Web Access, First Seen Provider, Multiple Services, Usage Volume Anomaly and After Hours. A heavy user of an unsanctioned provider can reach 60 in one day. Before enabling, record sanctioned providers and users in `ai_sanctioned_entities` (common package). That removes the activity at the source, for every detection.
- **One dominant detection.** One detection with a high score, or one that fires several times a day, can supply most of a total. `top_detection_share` shows how much. In the proxy run below, the top rule supplied 68–87 % of a qualifying total on average. The customizations macro can drop rows above a share you choose.
- **Single-detection totals are ignored here on purpose.** A user with one 80-point event and nothing else gets no medium notable. That risk is already on the user, and the HDSI and ES generic risk-threshold rules still see it. Set `min_detections` to 1 if the SOC wants those users in this queue.
- **Person key trade-offs.** Stripping `@domain` and `DOMAIN\` merges one person's formats without needing ES identities. It also merges different people who share an account name across domains or forests (`jdoe@a.com` and `jdoe@b.com`). It does not merge an account name with a different UPN local part (`jsmith` and `john.smith@…`).
- **No `risk_suppression` tag filter.** Neither band rule applies an eventtype-based suppression tag. On two validation tenants, adding `NOT tag="risk_suppression"` to the base search made Splunk report "The specified search will not match any events" and return nothing. One tenant had no such tag; the other had a tag that pointed to a deleted eventtype. If a tenant does use such a tag, add `| search NOT tag="risk_suppression"` after the base search in both band rules, never inside the base search.
- **System risk is out of scope.** Host-only AI risk is never totalled here.
- **Renamed detections.** A tenant copy of a detection counts only if it keeps `- HDSI AI ` in its name or still writes `detection_id=hdsi_ai_*`.
- **Volume equals the band population.** Every person in the band with two or more contributing detections produces one notable a day. Measure that number with the threshold SPL before enabling.

### Validation
Read-only live tests on 2026-10-09 across 4 production ES tenants. None of the HDSI AI detections is deployed, so `index=risk` held no HDSI AI events in any tenant over 7 days. The logic was proven three ways:
- **Real runs**, which were expected to return 0 rows.
- **A synthetic run** over hand-built risk events.
- **A proxy run** over each tenant's real risk from all of its rules. It used the same pipeline with the HDSI AI membership filter removed.

| Tenant | User risk events / 24 h (all rules) | HDSI AI risk events (7 d) | Parses (search + 3 drilldowns) | Real run, 24 h | Proxy: people in band by total → with ≥ 2 rules | Proxy, same day 1 week earlier |
|---|---|---|---|---|---|---|
| A | ~41,000 | 0 | OK | 0 rows, no errors | 12,977 → 293 | 124 |
| B | ~52,000 | 0 | OK | 0 rows, no errors | 4 → 0 | 0 |
| C | ~8,800 | 0 | OK | 0 rows, no errors | 1,194 → 7 | 2 |
| D | 2 | 0 | OK | 0 rows, no errors | 2 → 0 | 0 |

Run time:
- **Tenant A, full rule:** 7–25 s. That breaks down as about 6 s for the risk base search and about 6 s for the notable-index guard.
- **Other tenants:** under 6 s.
- **Drilldowns:** up to about 20 s on Tenant A, because they read the data model.

Proxy scores come from non-AI content, so they do not predict AI notable volume. They do show that `min_detections=2` removes 98–100 % of in-band totals that one rule built on its own.

**Synthetic test (identical on all four tenants).** 23 people were built from risk events with the real stanza names and fields (`source`, `risk_object`, `risk_object_type`, `risk_score`, `detection_id`, `ai_kill_chain_phase`, `tag`). The rule raised exactly 6 notables:
- 65 points from 3 detections.
- 65 points from `Dave@Corp.example` and `CORP\dave`, merged into one person.
- 65 points from `Mia` and `MIA`.
- 60 points from a renamed rule matched by `detection_id` plus a standard rule; the boundary value is included.
- 89 points from 2 detections.
- 70 points from 2 detections, one of them tagged `risk_suppression`. The tag is deliberately not applied.

It correctly ignored the rest:
- **Critical band:** 95, exactly 90, and 95 split across `Oscar@…` and `CORP\oscar`.
- **Single-detection totals:**
  - a single 80-point event;
  - 60 points from four firings of one detection;
  - 65 points from a clone and its original with the same `detection_id`.
- **Excluded or non-person accounts:** `unknown`, empty, `(null)`, `HOST$`, `root`, and a bare `Administrator`. Two different hosts' local `administrator` accounts stayed separate and below the threshold.
- **Out-of-scope events:** a system risk object, an `HDSI RBA AI` aggregator source, and a non-AI ES rule.

The critical rule's search, run on the same events, raised exactly the 3 critical-band people, so the two rules did not overlap. With a critical notable injected for one in-band person, that person's medium notable was suppressed.

The previous logic, run on the same kind of events, raised 9 notables. They included `unknown` and a machine account. Three people were also at 90 or above, so the critical rule fired for them too. The previous logic also split `Dave@…` and `CORP\dave` into two people below the threshold.

Defects fixed from v1.0:
- `unknown`, empty and machine-account risk objects could raise notables.
- Users at or above the high threshold fired both this rule and the critical rule.
- A single detection could cross the threshold on its own.
- UPN and `DOMAIN\` forms were not merged.
- A 4 h suppression re-alerted up to six times a day on the same total.
- MITRE T1078 (Valid Accounts) did not describe the content.
- The drilldowns matched any source containing "HDSI AI".
- The notable gave no breakdown.

### Deployment
The package ships with `enable_alerting: false`. Before enabling:
1. Confirm the HDSI AI detections have written user risk in the tenant for at least two weeks.
2. Run the threshold SPL above.
3. Set the two `ai_detection_config` rows for the tenant if the defaults do not fit.
4. Confirm the expected daily notable count with the SOC.

Enable this rule and `hdsi_rba_ai_user_critical_risk_threshold_exceeded` together, with the same filter, person-key and excluded-account definitions. This aggregator creates notables and writes no risk. Enabling it, and any threshold change, must be one separately approved change.
