## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule runs once a day and compares each user's AI usage on the last complete day with that user's own baseline over the 14 days before it. It looks at two measures: AI sessions or requests, and MB uploaded. Firewall App-ID sessions (Network_Traffic) and web/SSE log requests (Web: proxy, SSE/CASB, firewall URL-filtering or enterprise-browser logs) are scored separately, each against its own baseline. A day far above the user's normal pattern can be a bulk paste or upload of data into an AI service, a script or agent running under the user's identity, or a compromised account. The rule creates risk on `user`, suppresses repeats for that user for 23 hours (82800 s, shorter than the daily cron so that a run finishing earlier than the previous one never hides a second anomalous day), and does not create a notable event.

### Prerequisites

- **At least one of these, accelerated, with user attribution:**
  - `Network_Traffic.All_Traffic` with `app` (firewall App-ID, for example Palo Alto) and `user` (User-ID).
  - `Web` with `user` and either `url_domain` or `site`. SSE/CASB products that write an app name to `site` (for example Netskope) are supported, and so are firewall URL-filtering and enterprise-browser audit logs mapped to `Web` (Tenant A).
  - Rows without a usable user are dropped. Inbound server logs (load balancer, WAF, IIS) carry no user, so they never score.
- **`bytes_out`** for the upload measure. Without it the rule still scores on request counts, but those rows are weaker evidence: they score lower and are not labelled as exfiltration (see Scoring).
- **Acceleration range of at least 15 days.** The rule reads summaries only (`summariesonly=t`) from `-15d@d` to `@d`, so the `Web` and `Network_Traffic` acceleration `earliest_time` must reach back at least 15 days (`-15d` or wider; the CIM-app setting is `-3mon` on three of the four validation tenants). A shorter range does not fail; it silently shortens every baseline. With `-1w` (Tenant A) only about 7 history days exist, and with a fixed 7-day minimum only users active on every one of those days, weekends included, could be scored, which biases the rule toward always-on and service accounts. The rule therefore scales the required active days to the history days that really hold summaries (see How it works): 7 of 14 at full coverage, 4 at about 7 days. That keeps the rule working on short ranges, but on 4-6 day baselines and with 7-day weekly cycles barely covered, so widening the acceleration range is the real fix. Check it with:

  ```text
  | rest /servicesNS/-/-/datamodel/model splunk_server=local count=0
  | search title IN ("Web","Network_Traffic")
  | spath input=acceleration path=enabled output=accel_enabled
  | spath input=acceleration path=earliest_time output=accel_earliest_time
  | table title accel_enabled accel_earliest_time
  ```

  Widening the range is a data model change on the search head (more summary storage and a backfill), so it needs its own approval.
- **Newly accelerated data model:** with fewer than 8 covered history days the requirement drops to the 4-day floor; with fewer than 4 the rule returns nothing.
- **ES lookups:** `identity_lookup_expanded` (`bunit`, `category`, `priority`), read by the common macros for the allow-list group key and the risk multiplier. The rule itself does no identity lookup.
- **Common package `hdsi_ai_rba_common`:** `ai_domains_filter` with the `ai_provider_domains` (including its `traffic_class` column) and `ai_provider_apps` lookups, `ai_unsanctioned_filter(3)` with `ai_sanctioned_entities`, and `ai_risk_multiplier` with `ai_department_sensitivity`.

### How it works

- **Network_Traffic branch:** `tstats` reads AI App-ID sessions (`..._app_prefilter`) per user per day, excluding blocked sessions. `ai_domains_filter` resolves the App-ID with `ai_input_type="app"`.
- **Web branch:** `tstats` reads candidate AI hosts and app names (`..._web_prefilter`) per user per day, excluding blocked requests. `ai_domain` is `url_domain`, or `site` when `url_domain` is empty. The evidence label is `web/SSE log`, because the Web data model can hold proxy, SSE/CASB, firewall URL-filtering or enterprise-browser logs.
- **Daily baseline** (`..._daily_baseline`, shared by both branches):
  1. Keeps the usage types in `..._usage_types` (IDE coding assistants are left out by default), keeps only interactive hosts and drops rows without a usable user. Hosts that `ai_domains_filter` marks `ai_traffic_class` = `background` (for example `gemini.gstatic.com`, which Tenant A loaded for more users than `gemini.google.com`, Copilot telemetry and the ChatGPT/OpenAI analytics and auth hosts) or `site` (vendor download sites such as `ollama.com`) are loaded without deliberate AI use, so they are not counted.
  2. Removes allow-listed entries (`ai_unsanctioned_filter`): `user|provider`, `user|*`, `group|provider`, `group|*` and the organisation-wide `*|provider` key in `ai_sanctioned_entities`. The group is the identity `bunit`, which the common macro looks up itself.
  3. Sums each user's AI activity per day across providers.
  4. Takes the mean and standard deviation over the history days only. The evaluated day is left out, so a spike cannot inflate its own baseline.
  5. Measures `history_days`, the history days that really hold summaries for that evidence source. A day counts when its population of users with AI activity is at least 2 % (`..._coverage_share`) of the busiest day, so a few rows from stale old summaries do not count, while quiet weekends do.
  6. Keeps users with at least `required_days` active baseline days: `min(7, max(4, ceiling(7 x history_days / 14)))`. That is 7 at full coverage and 4 when the summaries hold only about a week.
  The baseline uses active days only. A day with no AI use is not counted as zero.
- **z-scores:** `z = (day - mean) / max(stdev, 0.5 x mean, 1)`. The floor stops a short or nearly constant history from turning a small change into a huge z-score. With the default threshold of 4, a day must reach at least 3 x the user's mean before it can score. In validation, a 0.25 x mean floor let a 2.4 x day on a steady firewall user reach z = 5.2.
- **Fleet-shift guard:** when 20 or more users are scored from one evidence source, the population's median z-score (if positive) is subtracted from every user's z-score. An organisation-wide change therefore does not fire for everyone at once.
- **Anomaly test:** a day is anomalous when z >= 4 and the count is at least the branch floor (100 web/SSE requests, or 500 firewall sessions), or when z >= 4 and MB uploaded >= 20. If a user is anomalous in both branches, only the stronger row is kept.
- **Risk message:** names the user, the anomaly type, the count with its unit (firewall App-ID `sessions` or web/SSE log `requests`), the baseline mean, the active baseline days against the covered history days, the z-scores, MB uploaded and the providers.
- **Scoring and labels:** the base score depends on the evidence.

  | Anomaly | Base score | `ai_kill_chain_phase` |
  |---|---|---|
  | Requests/sessions and upload both anomalous | 50 | `exfiltration` |
  | Upload only, z >= 8 | 40 | `exfiltration` |
  | Upload only | 30 | `exfiltration` |
  | Requests/sessions only, z >= 8 | 30 | `execution` |
  | Requests/sessions only | 20 | `execution` |

  A request-only day has no upload evidence. It fits heavy interactive use, a script or an agent running under the user's identity, so it scores lower and is not labelled as exfiltration. It still carries the rule's single ATT&CK annotation (`mitre_attack` = T1567), because the rule is built to surface exfiltration to AI services. On sources without `bytes_out` (Tenant A's Web data) every row is request-only. `risk_score = min(70, base x risk_multiplier)`, where `risk_multiplier` comes from the identity `bunit` sensitivity, x1.25 for privileged or critical identities, capped at 2.0. The `_risk` entry carries a literal 30 as the fallback score.
- **Drilldowns:** they use `user_dd`, the user with every backslash or double quote replaced by `*`. A `DOMAIN\user` value placed raw in a quoted SPL term can lose its backslash and match nothing; on Tenant A, where most users are `DOMAIN\user`, the `user_dd` form matched a `DOMAIN\user` identity's firewall sessions (32 of 32) and risk events.

### Tuning macros

| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_usage_volume_anomaly_filter` | `()` | Exclusions inside the Network_Traffic `tstats` (`All_Traffic.*` names), e.g. service accounts or an approved AI integration host. |
| `hdsi_ai_usage_volume_anomaly_web_filter` | `()` | Exclusions inside the Web `tstats` (`Web.*` names). On a Web data model that also holds inbound server logs, restrict it to the proxy/SSE indexes, e.g. `index IN ("proxy","netskope")`; this is the cheapest way to cut the Web branch run time. On a tenant with no user-attributed egress Web data, turn the branch off with `index="hdsi_web_branch_off"` (see Deployment). |
| `hdsi_ai_usage_volume_anomaly_app_prefilter` | enabled `ai_provider_apps` names except `google-gemini` | App-IDs the Network_Traffic branch reads. The specific Gemini App-IDs (`google-gemini-posting`, `-uploading`, `-downloading`, `-models`, `google-bard-base`, `google-notebooklm`) are kept: on Tenant A they covered 3-76 users a day, not the whole workforce. Add any App-ID you enable in the common lookup. |
| `hdsi_ai_usage_volume_anomaly_web_prefilter` | exact interactive AI hosts (`traffic_class` background and site hosts left out); 21 wildcard patterns (`*.base` for 15 high-volume chat/API provider bases plus 6 cloud AI endpoint patterns: Azure OpenAI, Azure AI Foundry, Azure AI Services, Bedrock, SageMaker, Vertex AI); app names in `site` | Hosts and app names the Web branch reads. Leading wildcards are expensive, so add `*.base` patterns only where needed. |
| `hdsi_ai_usage_volume_anomaly_usage_types` | `"web","api","cli","local_llm","model_registry"` | `usage_type` values that count. Add `"ide"` to baseline coding assistants too, and add their `*.base` patterns to the Web prefilter. |
| `hdsi_ai_usage_volume_anomaly_zscore` | `4` | Minimum z-score, after the fleet-shift correction. |
| `hdsi_ai_usage_volume_anomaly_min_requests` | `100` | Web branch: minimum web/SSE log requests on the day for a request anomaly. |
| `hdsi_ai_usage_volume_anomaly_min_sessions` | `500` | Network_Traffic branch: minimum firewall App-ID sessions on the day for a session anomaly. |
| `hdsi_ai_usage_volume_anomaly_min_mb` | `20` | Minimum MB uploaded on the day for an upload anomaly. |
| `hdsi_ai_usage_volume_anomaly_min_baseline_days` | `7` | Required active days in the 14-day history at full summary coverage. |
| `hdsi_ai_usage_volume_anomaly_min_baseline_floor` | `4` | Lowest requirement when summaries cover less (short acceleration range). Set it to `7` to refuse short baselines. |
| `hdsi_ai_usage_volume_anomaly_coverage_share` | `0.02` | Share of the busiest day's user population a history day needs to count as covered. |
| `hdsi_ai_usage_volume_anomaly_fleet_min_users` | `20` | Population size from which the fleet-shift guard applies. |
| `hdsi_ai_usage_volume_anomaly_daily_baseline` | shared pipeline | Not a tuning hook. |
| `hdsi_ai_usage_volume_anomaly_customizations` | `search *` | Post-scoring hook. Fields include `user`, `provider`, `evidence`, `count_unit`, `requests`, `mean_requests`, `z_requests`, `mb_out`, `mean_mb`, `z_mb`, `baseline_days`, `history_days`, `required_days`, `anomaly_type` and `risk_score`. |
| `hdsi_ai_usage_volume_anomaly_risk_score` | `search *` | Last pipe. Override `risk_score` here and keep it between 1 and 100. |

The thresholds used to live in `ai_detection_config` (`volume_anomaly_zscore`, `volume_anomaly_min_days`). This rule no longer reads those rows.

### Threshold

The defaults were calibrated on the two validation tenants with user-attributed AI data (see Validation). On Tenant A, z >= 4 flagged 3 of 47 scored firewall users and 29 of 736 scored Web users for one evaluated day. The floors then removed every Web row below 100 requests (25 rows of 6-72 requests) and one 457-session firewall day, leaving 2 firewall and 4 Web rows. The SSE tenant flagged 0-2 users a day over 4 evaluated days. Treat the defaults as a starting point.

The floors are noise floors, not the anomaly test: the z-score decides. Each floor only has to stop a z-qualifying day that is too small in absolute terms to be worth an analyst's time, so any value between the median and the p99 of a scored user-day for that branch works. Lower floors leave more of the decision to the z-score; a floor above the p99 means almost nothing can fire. The shipped floors sit at different points of that range on Tenant A, the only tenant with enough scored users to measure:

| Floor | Ships as | Tenant A scored user-day percentiles | Position |
|---|---|---|---|
| `..._min_requests` (Web) | 100 | p90 40, p99 334 requests | between p90 and p99 |
| `..._min_sessions` (firewall) | 500 | median 119, p75 717, p90 1,911 sessions | between median and p75 |
| `..._min_mb` | 20 MB | firewall p90 46 MB, p99 165 MB | below p90 |

The session floor is lower relative to its distribution because firewall users are few (47 scored) and a 3x day above 500 sessions is already a large absolute change. The MB floor is low on purpose: 20 MB of text sent to a chat service in one day is a lot of pasted data, and the z-score has to qualify the day as well. Raise either one if it produces more rows than you can review. Request counts per user are not comparable between products, so set the floors per branch and re-check after onboarding a new proxy or firewall source.

To derive tenant values, run the rule's search up to (not including) the `| eval count_unit=` line over `-15d@d` to `@d`, then append:

```text
| stats count AS scored_users
        median(requests) AS p50 perc75(requests) AS p75
        perc90(requests) AS p90 perc99(requests) AS p99
        perc90(mb_out) AS mb_p90 perc99(mb_out) AS mb_p99
        count(eval(z_requests>=4)) AS z4_no_floor
        count(eval(z_requests>=4 AND requests>=100)) AS z4_100
        count(eval(z_requests>=4 AND requests>=500)) AS z4_500
        count(eval(z_mb>=4 AND mb_out>=20)) AS mb_z4_20
        values(history_days) AS history_days values(required_days) AS required_days
        BY evidence
```

`history_days` below 14 means the acceleration range is short (see Prerequisites). Repeat it for a few evaluated days by shifting the window back one day at a time (`-16d@d` to `-1d@d`, and so on). Pick the lowest z-score and floors that give a handful of users a day.

### Known false positives / Limitations

- **Request counts depend on the log source.** Firewall App-ID counts sessions, proxies and URL-filtering logs count requests, and some SSE products log one event per app transaction. A user who moves from one product to another, or a log source that changes verbosity, shifts the counts. Baselines are per source for this reason.
- **Legitimate heavy days:** project deadlines, training, a new AI-enabled IDE or agent, or a sanctioned bulk task. Allow-list them in `ai_sanctioned_entities` (it supports an expiry date): a user and provider (`jdoe|openai`), a user for every provider (`jdoe|*`), an ES identity `bunit` and provider (`engineering|openai`), or a provider for the whole organisation (`*|openai`, for a sanctioned enterprise tenant). Provider names are matched lowercased. The system key is not used here, because both branches group by user only.
- **Ambient assistant traffic:** Gemini built into Google Workspace appears as the `google-gemini` App-ID for almost every user. It is left out of the Network_Traffic branch by default; the specific Gemini action App-IDs still count. On the Web side, `gemini.gstatic.com` is a static-asset host (Tenant A: 1,956 users a day against 1,495 for `gemini.google.com`); it and the other `traffic_class` background and site hosts are not counted. Microsoft 365 Copilot is opt-in (disabled) in the common lookups.
- **IDE coding assistants are not scored by default.** GitHub Copilot, Cursor and similar tools follow coding workload. On the SSE validation tenant they produced almost every anomaly at low thresholds. `hdsi_ai_code_assistant_network_connection` covers them.
- **Coverage gaps:** the Web prefilter reads subdomains only for the 15 listed provider bases and the 6 cloud AI patterns. For other providers, only the hosts listed in `ai_provider_domains` count.
- **No user attribution means no detection.** Firewalls without User-ID, DNS-only visibility, and unauthenticated proxies cannot feed this rule.
- **Cost:** the rule reads 15 days of two data models once a day. Measured full runs took 9-14 s on Tenants C and D, 562 s on Tenant A and 582-719 s on Tenant B.
  - On a 7-billion-session-a-day firewall, per-user grouping of AI App-IDs costs about 45 s per day of data.
  - On a very large Web data model, each leading-wildcard host pattern costs about 0.4-1.3 s per day of data. The full 131-pattern list cost up to 175 s per day, which is why only 15 bases carry wildcards.
  - Restricting `..._web_filter` to the proxy/SSE indexes is the most effective cut. On Tenant B the Web branch costs about 50 s per day of data (about 10 minutes a run) and finds no user-attributed AI request at all; filtering out `unknown` users in the `tstats` does not make it cheaper. Setting `..._web_filter` to `index="hdsi_web_branch_off"` (an index that does not exist) brought the 15-day Web read down to 1.5 s.
  - The Web branch runs as an `append` with `maxtime=1800`. At the default 60 s it was silently truncated on the large tenants.
- **Short acceleration range:** on a data model accelerated for less than 15 days the baseline is short, weekly cycles are barely covered, and a user's first busy Monday after a quiet week can look anomalous. The required days scale down to a 4-day floor rather than silently scoring only always-on accounts. Widen the acceleration range for a full baseline.
- **Web data without `bytes_out`:** Tenant A's Web data is firewall URL-filtering and enterprise-browser audit logs, not a proxy, and carries no upload bytes. Its Web rows can only fire on request counts, so they score 20-30 and are labelled `execution`, not `exfiltration`.
- **Drilldowns:** the two activity drilldowns apply the same `usage_type`, `traffic_class` and not-blocked filters as the rule, but they are not restricted by the web prefilter or the allow-list, so they can show slightly more than the risk message counts. They match the user through `user_dd` (backslash and quote replaced by `*`), which can in rare cases also match a second identity that differs only in that character.

### Validation

Read-only live tests, 2026-10-09, on 4 production ES tenants. The evaluated day was the last complete day at test time.

| Tenant | User-attributed AI data | Acceleration range | Parses (rule + 3 drilldowns) | Rows | Runtime | Notes |
|---|---|---|---|---|---|---|
| A | Firewall App-ID with User-ID; Web data from firewall URL-filtering and enterprise-browser audit logs, with users but no `bytes_out` | `-1w` (Web and Network_Traffic) | Yes | 6 (full run before the last changes) | 562 s | 7 covered history days for the firewall and 8 for Web, so `required_days` = 4; 47 firewall and 736 Web users were scored. Rows: 2 firewall OpenAI days at 16x and 5.5x the user's mean sessions with 24x and 5x the mean upload (score 50), and 4 Web days at 4.6-9.5x the mean requests (104-498 requests). Those 4 request-only rows scored 30-40 then; under the current scoring they score 20-30 and are labelled `execution`. One of them was Gemini-only and may drop now that `gemini.gstatic.com` is not counted. The final run after these changes was capped at 120 s (light test load) and returned no FATAL or ERROR before the cap. No empty or `unknown` user; every score is 70 or below. With a fixed 7-day minimum the same day gave 2 rows and only users active on all 7 days were eligible. The `google-gemini` App-ID covered more than 120,000 users in 30 days and is excluded. |
| B | Small DNS-proxy subset in Web, otherwise inbound load-balancer logs; no user-attributed AI web requests; no AI App-IDs | `-3mon` | Yes | 0 | 582-719 s | Nearly all of the run time is the Web prefilter scanning a very large inbound Web model that cannot contribute: on the last complete day it matched AI hosts only for the `unknown` user (0 attributed users, about 50 s per day of data). Turn the Web branch off or restrict it to the proxy index with `..._web_filter`; the off switch cut the 15-day Web read to 1.5 s. The final run was capped at 120 s with no FATAL or ERROR. |
| C | SSE (app name in `site`); AI App-IDs carry no user | `-3mon` | Yes | 0 | 12-14 s | 14 covered history days, `required_days` = 7; 7 non-IDE users scored (request p99 6, so only uploads can fire). With IDE assistants counted (calibration), 119-131 users were scored per day and z >= 4 with the floors fired on 0-2 a day over 4 evaluated days. |
| D | None (inbound IIS only) | `-3mon` | Yes | 0 | 9-10 s | No user-attributed AI activity. |

Before v1.1, the rule read 30 days of Web data without a prefilter. It hit the 300 s limit on A and B and returned 0 rows on C and D. It also had these defects:

- It counted provider-days as baseline days.
- It mixed per-provider rows with a per-user baseline.
- The evaluated day was included in its own baseline.
- It had no user or inbound-traffic guard.
- It used `src="unknown"`.

### Deployment

The package ships with `enable_alerting: false`. Before enabling it:

1. Confirm that at least one branch has user-attributed AI data and that its data model acceleration `earliest_time` reaches back at least 15 days (Prerequisites SPL). If it does not, either approve widening the acceleration range first or accept the shorter, noisier baseline.
2. Check that the Web branch can contribute. Run this over the last complete day (`-1d@d` to `@d`):

   ```text
   | tstats summariesonly=t allow_old_summaries=t count from datamodel=Web
       where NOT Web.action="blocked" `hdsi_ai_usage_volume_anomaly_web_prefilter` `hdsi_ai_usage_volume_anomaly_web_filter`
       NOT Web.user IN ("unknown","-")
       by Web.user index sourcetype
   | stats dc(Web.user) AS attributed_users sum(count) AS requests BY index sourcetype
   ```

   If it returns no attributed users, set `hdsi_ai_usage_volume_anomaly_web_filter` to `index="hdsi_web_branch_off"` (or to the proxy/SSE indexes that do carry users) so the rule does not spend minutes a day on inbound server logs. Do the same check for Network_Traffic with the `..._app_prefilter` macro and `All_Traffic.user`.
3. Run the Threshold SPL for several evaluated days.
4. Set the z-score and floors.
5. Measure the daily risk volume and the search runtime at 03:30.

The rule is risk-only. Enabling it, and disabling any rule it replaces, must be one separately approved change.
