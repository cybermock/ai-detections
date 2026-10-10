## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This risk aggregator raises a notable when one person (a user, together with the hosts attributed only to that user) or one unattributed system collects HDSI AI risk across several different kinds of AI behaviour in 24 hours. The rule needs at least 3 of 6 vectors, and at least one of them must be high impact: data exposure, risky access, or adversarial AI. Heavy but ordinary AI use does not fire it on its own: browsing to unsanctioned AI sites, an unusual usage volume, AI desktop and CLI tools, and ordinary coding-agent work (Claude Code, Codex or the Copilot agent running builds, package installs, `git push` or `curl`) all count as normal-impact vectors. It reads `index=risk` and creates a notable when a person or system newly reaches the threshold or adds a vector (`action.notable = 1`). It writes no risk (`action.risk = 0`).

### Prerequisites
- **ES risk index.** The search reads `index=risk`, the default index behind `Risk.All_Risk`. If your tenant writes risk to a different index, change the base search. The drilldowns use `| from datamodel:"Risk.All_Risk"`.
- **HDSI AI detections writing risk.** The rule has nothing to aggregate until at least three HDSI AI detections from different vectors are enabled with `action.risk = 1`. It matches contributing risk events on `source="* - HDSI AI * - Rule"`, the stanza names the packages ship with. If you rename a detection's stanza, it stops counting.
- **Fields read from risk events.** `risk_object`, `risk_object_type`, `risk_score` (and `calculated_risk_score` when ES risk factors set it), `risk_message`, `source`, `tag` (events tagged `risk_suppression` are skipped), `_indextime`, plus these result fields that the HDSI AI rules write and ES copies into each risk event:
  - `detection_id`. If it is missing, the rule derives the package id from the stanza name.
  - `ai_kill_chain_phase`. This is only used for rules the vector map does not list.
  - `risk_category` (Agent Autonomous Action Detection only). Its high-signal risk events (`credential_access`, `persistence`, `system_change`) count as adversarial; its `agent_activity` events count as local tooling. If `risk_category` is missing, `risk_tier=sensitive` is used instead; if both are missing, the event counts as local tooling.
  - `user`, read from system risk events to attribute a host to one person.
  - `annotations.mitre_attack` / `mitre_attack`, reported as `contributing_mitre`.
- **Common package.** The rule uses no common macros or lookups at run time. It is listed as `prereq_packages: hdsi_ai_rba_common` because the contributing detections need that package.

### How it works
1. Reads 24 hours of HDSI AI risk events from `index=risk` for `user` and `system` risk objects. Aggregator output (`HDSI RBA AI ...`), non-AI content, `other` objects, machine accounts (`*$`) and events tagged `risk_suppression` are excluded.
2. Drops risk objects that are empty, `unknown`, `-`, `n/a`, `na`, `none`, `null` or `undefined`, so a placeholder identity can never accumulate vectors. User objects that are built-in OS accounts (`root`, `system`, `nt authority\system`, `local service`, `network service`; macro `hdsi_rba_ai_multi_vector_risk_builtin_accounts`) are dropped too, because one shared account name would merge unrelated hosts into a false hotspot. Objects are keyed in lower case (`risk_object_key`), so `Bob@corp`, `bob@corp` and `BOB@corp` are one object.
3. Works out `detection_key` for each event. This is the `detection_id` written by the rule. When that field is missing, the package id is derived from the stanza name (`Network - HDSI AI Access Via VPN/Proxy Evasion - Rule` → `hdsi_ai_access_via_vpn_proxy_evasion`). This derivation was checked against all 45 HDSI AI stanza names.
4. Maps each detection to one of six vectors (`hdsi_rba_ai_multi_vector_risk_vector_map`). All 38 released risk-emitting HDSI AI rules are listed, plus the 4 incubating ones (so they count correctly if promoted). A future rule falls back to its `ai_kill_chain_phase`. The health checks and the hunting-only API discovery search are ignored.

   | Vector | Impact | Detections |
   |---|---|---|
   | `shadow_usage` | normal | Unsanctioned Web Access, First Seen Provider For User, Repeated Unsanctioned Access Burst, Multiple Services In Single Session, New Provider Adoption Velocity, DNS Queries To AI Domains, API Access From Non-Dev Endpoint, Code Assistant Network Connection |
   | `usage_anomaly` | normal | After Hours Service Usage, Time-of-Day Usage Pattern Anomaly, Usage Volume Anomaly, User Peer Group Usage Anomaly |
   | `local_tooling` | normal | Unsanctioned CLI Execution, Unsanctioned Desktop App Execution, Scripted CLI Invocation, Local LLM Framework Execution, Local LLM Listening Port Detected, Agent Framework Execution, MCP Server Execution, LLM Model File Download, Browser Extension Activity, **Agent Autonomous Action Detection (`agent_activity` events: routine and development tiers)** |
   | `risky_access` | **high** | Access Via VPN/Proxy Evasion, Access From Unmanaged Device, Usage From Personal Account / OAuth Mismatch, Privileged Account Service Usage |
   | `data_exposure` | **high** | High Volume Upload To AI Service, DLP Violation On Service Upload, Sanctioned DLP Violation, Personal Email To AI Service Upload Correlation, Gradual Data Exfiltration Via AI, Copy-Paste Correlation To AI Service, Usage Following Data Access Spike, Browser Extension High-Volume Data Transmission, Suspicious Model File Exfiltration, API Key Exposure In Code/DLP |
   | `adversarial` | **high** | Prompt Injection Indicators In Web Uploads, Generated Phishing Indicators, Deepfake Tool Execution/Access, Voice Cloning API Access, Compromised Plugin/Extension Installation, Assisted Lateral Movement, **Agent Autonomous Action Detection (high-signal events only:** `risk_category` credential_access, persistence or system_change) |

   Access From Unmanaged Device, Usage From Personal Account / OAuth Mismatch, DLP Violation On Service Upload and Browser Extension High-Volume Data Transmission are incubating (not released; see `saved_searches/incubating/`). The vector map keeps them so they count once promoted; until then they contribute nothing.

   Agent Autonomous Action Detection writes one `agent_activity` risk event (score 10 to 25) per user and host per day for ordinary agent work, including the development categories (package installs such as `pip install`/`npx -y`, `git push`, `curl`/`wget`, recursive deletes), and a separate risk event per high-signal category (`credential_access` such as a `.env` or credential-store read, `persistence`, `system_change`). Only the high-signal events count as `adversarial`. Counting `agent_activity` as adversarial would let one developer reach 3 vectors, including a high-impact one, from one ordinary coding session (CLI execution → local_tooling, the agent's API traffic → shadow_usage, `pip install` or `git push` → adversarial). It therefore counts as `local_tooling`.
5. **Hosts are folded into their user.** A system risk object is attributed to a user when every `user` value on its risk events in the window is the same single user (events with no `user`, such as DNS-keyed risk, do not break the attribution). When that user also has user-type HDSI AI risk in the window, the host's events are merged into the user's object. The host-only evidence (DNS queries, an unmanaged-device hit, a local LLM listening port) then counts toward the user's vectors instead of being lost, and the host never produces a second notable for the same activity. The merged hosts are listed in `related_systems`. A host with no attributed user, or with two or more users, stays a separate `system` object. Machine accounts and the built-in accounts above never attribute a host, so a host whose risk events name only `root` or `SYSTEM` stays a `system` object.
6. Aggregates per user or system: `vector_count`, `vectors`, `new_vectors` (vectors first indexed inside the rising-edge window), `high_impact_count`, `high_impact_vectors`, `detection_count`, `vector_detections` (vector: detection), `risk_event_count`, `total_risk`, `max_risk_score`, `contributing_mitre` (techniques of the contributing rules), `attributed_users` (unmerged systems only), `related_systems` and `firstTime`/`lastTime`.
   `risk_event_count` and `total_risk` count each contributing result once. Endpoint rules write a user and a host risk event from the same result row; once that host is merged into the user, the pair (same `source`, `_time` and `risk_message`) is counted once and its score shared between the two events, so a merged user's `total_risk` is not doubled compared with an unmerged system. The score is `calculated_risk_score` when ES risk factors set it, otherwise `risk_score`.
7. Fires when `vector_count >= min_vectors` (3), `high_impact_count >= min_high_impact` (1), **and** at least one of the object's vectors was first indexed in the last 65 minutes (`hdsi_rba_ai_multi_vector_risk_new_vector_window`, on `_indextime` so rules that write an older `_time` still count). This is a rising edge: the rule fires when an object reaches the threshold or adds a vector, not on every run while it stays above it.
8. Suppression is set to `risk_object_key,risk_object_type,vector_count` for 24 hours, on the lower-case key so a change of case between risk events does not raise a duplicate. Within 24 hours an object therefore produces one notable per vector count it reaches: 3 vectors, then again at 4 if it adds one. The rising edge stops a second, smaller notable when a vector ages out of the rolling window (4 → 3 without new evidence). It can still happen in one corner case: a vector ages out and, in the same hour, another vector reappears after a gap of almost a day, which changes the count to a value not yet notified. The cron runs every 15 minutes over the last 24 hours.

The notable title is `HDSI AI Multi-Vector Risk for <type> <object> (<n> vectors)`. The description lists the vectors, the high-impact vectors, the newly added vectors, the number of contributing detections, the total risk and the merged hosts. The static annotation, and the notable's `mitre_attack` field, are T1588.007 (Obtain Capabilities: Artificial Intelligence); the contributing rules' own techniques are in `contributing_mitre`.

The three drilldowns (contributing AI risk events, AI risk summarised by detection, and all risk from any content) filter on `risk_object IN ($contributing_objects$)`. `contributing_objects` is a quoted, comma-separated list of the user's key and every merged host (backslashes are doubled so `DOMAIN\user` identities match), so the drilldowns show the host-only evidence too.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_rba_ai_multi_vector_risk_filter` | `()` | An inline exclusion in the base `index=risk` search. Use risk event field names, for example `NOT risk_object IN ("svc_*")`, or `risk_object_type="user"` to alert on users only (hosts are then never merged either). |
| `hdsi_rba_ai_multi_vector_risk_vector_map` | eval `case()` | Maps each detection to a vector. Move a rule to another vector, or set it to `null()` to stop it counting. |
| `hdsi_rba_ai_multi_vector_risk_high_impact_vectors` | `"^(data_exposure\|risky_access\|adversarial)$"` | A regex of the vectors that count as high impact. |
| `hdsi_rba_ai_multi_vector_risk_min_vectors` | `3` | The number of distinct vectors (of 6) that must be reached in 24 hours. This replaces the `multi_vector_categories` row of `ai_detection_config`, which this rule no longer reads. |
| `hdsi_rba_ai_multi_vector_risk_new_vector_window` | `"-65m"` | The rising-edge window, on index time. Set it to `"-24h"` for level-triggered alerting, for example for one run at deployment so objects that already meet the threshold are reported. |
| `hdsi_rba_ai_multi_vector_risk_builtin_accounts` | regex | Built-in OS account names (lower case) that are never used as a user object or to attribute a host. Add tenant service accounts here. |
| `hdsi_rba_ai_multi_vector_risk_min_high_impact` | `1` | The number of distinct high-impact vectors that must be reached. Set it to `0` to alert on breadth alone; this is not recommended. |
| `hdsi_rba_ai_multi_vector_risk_customizations` | `search *` | A post-aggregation hook, for example `search total_risk>=60` or `search NOT attributed_users="svc_*"`. |

### Threshold
Start with 3 vectors, 1 of them high impact. After the contributing detections have written risk for 14 days, measure how wide each object's activity is. This SPL applies the same exclusions, detection keys, vector map and host-to-user merge as the rule, per calendar day (the rule uses a rolling 24 hours and fires again when an object adds a vector, so expect slightly more notables than `would_fire_3`). Raise `min_vectors` to 4 if most 3-vector notables are benign power users:

```spl
index=risk source="* - HDSI AI * - Rule" risk_object_type IN ("user","system") risk_object=* NOT risk_object IN ("*$") NOT tag="risk_suppression" earliest=-14d@d latest=@d `hdsi_rba_ai_multi_vector_risk_filter`
| eval day=strftime(_time, "%F"), risk_object_key=lower(trim(mvindex(risk_object, 0)))
| where isnotnull(risk_object_key) AND NOT in(risk_object_key, "", "unknown", "-", "n/a", "na", "none", "null", "undefined") AND NOT (risk_object_type="user" AND match(risk_object_key, `hdsi_rba_ai_multi_vector_risk_builtin_accounts`))
| eval detection_label=replace(replace(source, "^[^-]+ - HDSI AI ", ""), " - Rule$", "")
| eval detection_key=if(match(mvindex(detection_id, 0), "^hdsi_ai_[a-z0-9_]+$"), mvindex(detection_id, 0), "hdsi_ai_".trim(replace(lower(detection_label), "[^a-z0-9]+", "_"), "_"))
| `hdsi_rba_ai_multi_vector_risk_vector_map`
| where isnotnull(ai_vector)
| eval user_key=lower(trim(mvindex(user, 0)))
| eval attributed_user=case(risk_object_type!="system", null(), mvcount(user)>1, "__multiple__", isnull(user_key) OR in(user_key, "", "unknown", "-", "n/a", "na", "none", "null", "undefined") OR like(user_key, "%$") OR match(user_key, `hdsi_rba_ai_multi_vector_risk_builtin_accounts`), null(), true(), user_key)
| eventstats dc(attributed_user) as host_user_count values(attributed_user) as host_users by day risk_object_key risk_object_type
| eval owner_key=case(risk_object_type="user", risk_object_key, host_user_count=1 AND host_users!="__multiple__", host_users, true(), null())
| eventstats count(eval(risk_object_type="user")) as owner_user_events by day owner_key
| eval merged=if(risk_object_type="system" AND isnotnull(owner_key) AND owner_user_events>0, 1, 0)
| eval group_key=if(merged=1, owner_key, risk_object_key), group_type=if(merged=1, "user", risk_object_type)
| eval hi=if(match(ai_vector, `hdsi_rba_ai_multi_vector_risk_high_impact_vectors`), ai_vector, null())
| stats dc(ai_vector) as vectors dc(hi) as high_impact by day group_key group_type
| stats count as objects count(eval(vectors>=2)) as two_plus_vectors count(eval(vectors>=3)) as breadth_only_3 count(eval(vectors>=3 AND high_impact>=1)) as would_fire_3 count(eval(vectors>=4 AND high_impact>=1)) as would_fire_4 by day group_type
```

`breadth_only_3` shows how many objects the high-impact requirement holds back. Aim for no more than a few notables a day. Each one should show a combination that an analyst would follow up.

### Known false positives / Limitations
- **Developers and AI champions.** Engineers who run AI CLIs, local models, agent frameworks and MCP servers (`local_tooling`) and reach AI providers (`shadow_usage`) need only one high-impact vector to fire. Ordinary coding-agent work (builds, package installs, `git push`, `curl`) stays in `local_tooling`. Typical paths to a notable are a high-signal coding-agent event (a Claude Code or Codex session that reads a `.env` file or credential store, creates a scheduled task or service, or runs `sudo`/registry/firewall changes; `credential_access` includes routine `.env` reads by agents, so some of these will be benign), use from a personal or unmanaged device (`risky_access`), or a privileged account using AI (`risky_access`). Review them with the "Summarize AI risk by detection" drilldown. Exclude known AI engineering groups through `_filter` (by `risk_object`) or `_customizations` instead of loosening the rule, or re-map the agent rule's `credential_access` events to `local_tooling` in the vector map if `.env` reads by agents are expected in your tenant.
- **Users use different identifier formats.** One person's activity is split when Web/SSE rules score a UPN while endpoint rules score `DOMAIN\sam` or a bare `sam`. Each identity then reaches fewer vectors. ES identity correlation does not merge these values in `risk_object`. If your tenant mixes formats, normalise identities in the contributing rules.
- **Hosts use different identifier formats.** DNS and network rules (DNS Queries To AI Domains, Access From Unmanaged Device, Access Via VPN/Proxy Evasion on DNS) key system risk on the source IP, while endpoint rules (CLI, desktop app, agent, MCP, listening port) key it on the hostname. One laptop's host-only vectors are therefore split between an IP object and a hostname object. In 24 hours of live system risk (all content), Tenants A and B were about 90% IPv4 while Tenant C was about 91% short hostnames, and all three had both forms. An IP-keyed host is merged into a user only when its own risk events carry that `user`, so DNS-only evidence keyed on a DHCP address usually stays a separate, low-breadth system object. Normalising `src` to a hostname with ES asset correlation in the contributing rules removes the split.
- **Host-to-user merging relies on the `user` field.** ES copies that field into system risk events. A rule that puts risk on a host but drops `user` from its output cannot attribute the host; its events stay on a separate system object unless another rule on the same host carries the user. A host used by two people is never merged, so a shared jump box or VDI host can fire as a system.
- **Depends on contributing coverage.** Only vectors whose detections are enabled can be counted. On a tenant with only DNS and endpoint data, five of the six vectors are still reachable, through few rules: `shadow_usage` (DNS Queries To AI Domains, Code Assistant Network Connection), `local_tooling` (CLI, desktop app, local LLM, agent and MCP rules), `risky_access` (the DNS branch of Access Via VPN/Proxy Evasion, and Access From Unmanaged Device once that incubating rule is promoted and enabled), `data_exposure` (API Key Exposure In Code/DLP, on `Endpoint.Processes`) and `adversarial` (Agent Autonomous Action high-signal events, Deepfake Tool Execution, Compromised Plugin Installation). `usage_anomaly` needs Web or Network_Traffic data, and the upload, DLP and email correlation rules in `data_exposure` need proxy, DLP or email data.
- **Drilldown tokens.** `contributing_objects` is inserted into the drilldown as written. A risk object containing a double quote would break the drilldown search (not the rule).
- **Rising edge at deployment.** An object that already meets the threshold when the rule is first enabled, with no vector first indexed in the last 65 minutes, is not reported until it adds a vector. Run the rule once with `new_vector_window` set to `"-24h"`, or use the threshold SPL, to see existing objects.
- **Renamed stanzas stop counting.** The base search matches `* - HDSI AI * - Rule`. A tenant copy renamed to a different pattern is not seen.
- **The 24-hour window is rolling, not chained.** The rule does not require the vectors in any order. Ordered progression is covered by `hdsi_rba_ai_data_collection_kill_chain`. Total-score thresholds are covered by the user risk threshold aggregators.

### Validation
Tested 2026-10-09 against 4 production ES tenants, using read-only search jobs. The final version (rising edge, paired-score counting, account hygiene, agent `risk_category` mapping) was re-parsed and re-run on all four tenants; the 7-day and 14-day figures are from the previous round, before those changes, and the base search only gained exclusions since then.

| Tenant | Risk index (24h) | HDSI AI risk events | Parses (search + 3 drilldowns) | Rows 24h (final) | Rows 7d | Threshold SPL (14d) | Notes |
|---|---|---|---|---|---|---|---|
| A | ~48k events | 0 (not deployed) | OK | 0 (about 3s) | 0 | OK, 0 rows | A warning about a deactivated tenant event type appears because `NOT tag="risk_suppression"` evaluates event types; harmless. System risk is keyed mostly on IPv4, with some hostnames and FQDNs. |
| B | ~53k events | 0 | OK | 0 (about 2s) | 0 | OK, 0 rows | |
| C | ~22k events | 0 | OK | 0 (about 3s) | 0 | OK, 0 rows | 95% of system risk events carry `user`, so host-to-user merging applies. System risk is keyed mostly on short hostnames. |
| D | ~12 events | 0 | OK | 0 (under 1s) | 0 | OK, 0 rows | Warns that the `risk_suppression` tag does not exist; harmless (no event is excluded). |

None of the HDSI AI detections are deployed in these tenants, so the logic of the final version was proven on Tenant A with 45 synthetic risk events (`makeresults`) that reproduce the risk-index fields and run through the full aggregation pipeline. The results matched what was expected:
- **Fired (6).**
  - A user whose laptop carried paired user/system events from the same rows plus a DNS-only event. The laptop was merged (`related_systems`), and `total_risk` was 75 (each result counted once), not the 140 that summing both events of each pair gives.
  - A `DOMAIN\user` identity in three cases with CLI, code-assistant and development-tier agent events plus one `credential_access` agent event (adversarial). The drilldown term has the doubled backslash.
  - A user whose agent event carried `risk_tier=sensitive` and no `risk_category` (fallback, adversarial).
  - A user with three vectors indexed more than 2 hours earlier and one new `risky_access` vector. It fired with `new_vector_list` = risky_access.
  - A host-only server with local_tooling, risky_access and shadow_usage.
  - A build host whose risk events name only `root`. It was not merged and fired as a `system` object.
- **Did not fire.**
  - A developer with an AI CLI, the code assistant's network connection and a development-tier `agent_activity` event (package install / `git push` / `curl`): 2 vectors, no high-impact vector.
  - A user with 4 vectors, including a high-impact one, all first indexed more than 2 hours earlier (only an already-present vector recurred). This is the rising edge: no second, smaller notable when a vector ages out.
  - `root`, `NT AUTHORITY\SYSTEM` (two cases), a machine account `WS01$` and `unknown`, each with 3 vectors including a high-impact one.
  - A user with 3 normal-impact vectors (no high-impact vector).

The threshold SPL on the same events reported 5 users and 2 systems in `would_fire_3`: the rule's 6 notables plus the already-notified user, which the per-day threshold count includes by design. The previous round's 40-event test also covered derived detection keys from stanza names without `detection_id`, mixed-case objects, unlisted future rules (kill-chain fallback), shared hosts with two users, aggregator and non-AI sources and `other` objects; those code paths are unchanged.

### Deployment
The package ships with `enable_alerting: false`. Enable it only after at least three HDSI AI detections from different vectors are writing risk in the tenant. Then run the threshold SPL above on 14 days of risk, confirm the vector map matches the rules enabled there, and review the expected daily notable count. This aggregator creates notables and writes no risk. Enabling it, and changing the threshold macros, must be one separately approved change.
