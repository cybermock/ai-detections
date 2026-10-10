## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This aggregator creates a **high notable** when one person's HDSI AI risk in a rolling 24 hours reaches the critical threshold (`high_risk_threshold` in the common `ai_detection_config` lookup, default **90**). It reads the user risk events that the HDSI AI detections write to `index=risk`. It adds up a person's UPN, `DOMAIN\account` and bare account forms together, and it ignores placeholder, machine, OS service and unqualified built-in accounts, which are never one person. The notable lists every contributing detection with its points, the AI kill-chain phases and the ATT&CK techniques, so an analyst can see at once why the user crossed the line. It is the upper band of the user threshold pair: `hdsi_rba_ai_user_risk_threshold_exceeded` (RISK-001, medium, `medium_risk_threshold` 60) covers the band below it, with the same identity key, exclusions and risk index (see the hand-off section). This rule writes no risk (`action.risk = 0`).

v1.0 summed every `search_name="*HDSI AI*"` user event by the raw `risk_object`. That meant `unknown`, `-`, `*****` and `HOST$` objects could cross the threshold and raise a high notable, and the same person scored as `jdoe@example.com` by a web detection and `EXAMPLE\jdoe` by an endpoint detection was counted as two people who each stayed under the threshold. Suppression was 2 hours on a 24-hour rolling window, so one user above the line could raise up to 12 notables a day. Its notable showed only a total.

### Prerequisites
- **ES risk index** (`index=risk`, set in `..._risk_index`) with user risk events from the HDSI AI detections. Fields used: `source`, `risk_object`, `risk_object_type`, `risk_score` (required), and `ai_kill_chain_phase`, `annotations.mitre_attack`, `mitre_attack`, `provider`, `provider_list` (context only, written by the detections; missing values do not drop rows). The rule only has input after HDSI AI detections that score **users** are enabled. DNS-only deployments score hosts and never reach it.
- **`Risk.All_Risk` data model** (part of ES) for the three drilldowns. The rule itself reads the risk index directly: on one validation tenant the data model search returned fewer `annotations.mitre_attack` values than the index for the same events (63,000 against 105,000 in 24 hours). If your tenant writes risk to a renamed or extra index, change `..._risk_index` and the Risk data model constraint together, or the drilldowns and the rule will disagree.
- **Common package `hdsi_ai_rba_common`**: lookup `ai_detection_config`, row `high_risk_threshold` (default 90 if the row is missing or not a number).

### How it works
- **Membership:** user risk events whose `source` (the saved search name) follows the HDSI AI stanza pattern `<Domain> - HDSI AI <Title> - Rule`, or whose `detection_id` starts with `hdsi_ai_` (catches a cloned or renamed detection that kept the SPL). In all 4 validation tenants `source` equalled `search_name` on 100% of risk events. `detection_id` is **not** the primary key: ES 8 writes its own UUID `detection_id` into risk events for content that carries detection metadata (seen on ESCU and some HL rules in Tenants A and B), so a detection's `eval detection_id=...` may not survive. Aggregators (`... - HDSI RBA AI ... - Rule`) and non-AI rules never match the pattern. The two health checks (`Audit - HDSI AI Health ... - Rule`) do match it, so they are excluded explicitly (`NOT source="* - HDSI AI Health * - Rule"`, and `detection_id="hdsi_ai_health_*"`); they ship without risk today, but a tenant that turns risk on for one would otherwise feed this rule.
- **Accounts that are never one person (`..._excluded_accounts`):** placeholders (`unknown`, `-`, `none`, `null`, `n/a`, `(null)`, `undefined`, all-asterisk masks such as `*****`), `$`-suffixed computer accounts, OS service identities (`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, anything under `NT AUTHORITY\`, `NT SERVICE\`, `IIS APPPOOL\`, `Window Manager\`, `Font Driver Host\`, `DWM-n`, `UMFD-n`), shared Unix accounts (`root`, `nobody`, `daemon`), `krbtgt`, and built-in accounts with no host or domain qualifier (a bare `administrator`, `admin`, `guest`, `defaultaccount`, `wdagutilityaccount`). Each of these would add up activity from many machines into one fleet-wide pseudo-user and raise a false critical notable. All four tenants carry such objects in the risk index today (for example 357 `*****` events a day on Tenant B, 129 `unknown` on Tenant C, and `system`, `root`, a bare `administrator` with 126 points from 3 rules on Tenant A, from non-AI rules), so this guard is not theoretical. Their risk stays in the risk index and in ES Risk Analysis.
- **One person, one key:** `..._user_key` sets `user_key = lower(risk_object)` with any `@domain` suffix and `DOMAIN\` prefix removed. Built-in local accounts are the exception: `HOST\Administrator`, `HOST\Guest`, `guest@domain` and the like keep their qualifier (written `host/administrator`), so the same built-in name on 18 different domains or machines stays 18 keys. Without this, Tenant A's `guest` key merged 18 different accounts (325 points) and `administrator` merged accounts from several machines. Web and SSE detections score UPNs and endpoint detections score account names, so without the merge a person's AI activity is split. On Tenant C, about 380 of the about 1,200 users with 60 to 89 points of (all-rule) risk in 24 hours appeared under more than one form (UPN, `DOMAIN\` or case variants; two runs a few minutes apart gave 379 of 1,193 and 383 of 1,197).
- **Totals:** risk is summed per `user_key`, per contributing detection, then per user. `total_risk` is the plain sum of `risk_score` (what ES Risk Analysis shows). The notable `user` is the raw risk object that carried the most points, so ES identity enrichment and urgency work on a real identity value. `risk_objects` lists every merged form. `account` (the key without host or domain) is used by the drilldowns to pre-filter the risk data model.
- **Threshold:** `total_risk >= high_risk_threshold` and `detection_count >= ..._min_detections` (ships as 1).
- **Notable fields:** `user`, `user_key`, `account`, `risk_objects`, `total_risk`, `high_risk_threshold`, `detection_count`, `risk_event_count`, `top_detection_risk`, `detections`, `detection_list` (up to 8 contributors with points, highest first), `phases`/`phase_list` (from `ai_kill_chain_phase`), `contributing_mitre_attack` (technique IDs only), `ai_providers` (up to 10), `firstTime`, `lastTime`.
- **Cadence and suppression:** every 15 minutes (`12-59/15`) over `-24h@m` to `now`. One notable per `user_key` per 24 hours (`alert.suppress.period = 86400s`). The static annotation is `T1588.007`; the per-notable techniques are in `contributing_mitre_attack`.

### Band hand-off with RISK-001
The two user threshold rules split one 24-hour total into two bands, so they never alert in the same band for the same person:

| Rule | Fires when |
|---|---|
| RISK-001 `hdsi_rba_ai_user_risk_threshold_exceeded` (medium) | `medium_risk_threshold <= total_risk < high_risk_threshold`, at least 2 distinct detections, and no notable from this rule for the same `user_key` in the last 24 hours |
| RISK-002 (this rule, high) | `total_risk >= high_risk_threshold`, at least `..._min_detections` (1) detections |

As shipped (2026-10-09) both rules read the same events and build the same key. Their `..._risk_index`, `..._user_key` and `..._excluded_accounts` macros are identical apart from the package prefix, both use the same HDSI AI membership and health-check exclusions on `source`, neither filters `tag="risk_suppression"` (see Limitations), and both take their thresholds from `ai_detection_config`, so the band edge moves for both rules at once. A user who climbs from medium to critical in one day gets one medium and then one high notable; that is an escalation, not a duplicate. A user whose total decays from critical back into the medium band gets no medium notable, because RISK-001 looks for this rule's notables.

**Contract you must keep when tuning.** The hand-off only works while:
- the three shared macros above, and the two `..._filter` macros, stay identical in both packages. If you add a service-account pattern or an exclusion to one rule, add it to the other;
- this rule keeps its stanza name `Threat - HDSI RBA AI User Critical Risk Threshold Exceeded - Rule` (RISK-001 names it in its `..._critical_rule` macro; change that macro if you rename this rule);
- this rule's notable keeps the `user_key` field. RISK-001 searches `index=notable` for this rule's `source` and joins on `user_key`, so a `..._customizations` that drops or rewrites `user_key` lets a medium notable follow a critical one.

The one intended difference is the minimum number of detections: RISK-001 needs 2, this rule 1. A user at 60 to 89 points from a single detection gets no notable from either rule; their risk is still visible in ES Risk Analysis. If you raise `..._min_detections` above 1, users at or above the critical threshold from a single detection get no notable from either rule.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_rba_ai_user_critical_risk_threshold_exceeded_risk_index` | `index=risk` | Where ES writes risk. Change it together with the Risk data model constraint, and keep it identical in RISK-001 |
| `hdsi_rba_ai_user_critical_risk_threshold_exceeded_filter` | `()` | Inline exclusions in the `index=risk` base search, using risk index field names, e.g. `NOT risk_object IN ("svc_*")` or `NOT source="Network - HDSI AI Unsanctioned Web Access - Rule"`. Add the same exclusion to RISK-001's `..._filter` |
| `hdsi_rba_ai_user_critical_risk_threshold_exceeded_user_key` | `eval user_key=lower(...)` with `@domain` and `DOMAIN\` removed, except for qualified built-in accounts | Identity key. Use `eval user_key=lower(trim(risk_object))` if separate email domains or forests reuse account names for different people. Must stay identical to RISK-001's `..._user_key` (see Limitations for the domain built-in alternative) |
| `hdsi_rba_ai_user_critical_risk_threshold_exceeded_excluded_accounts` | regex list (see How it works) | Accounts that are never one person. Ships without a service-account pattern (see Deployment step 3). Add tenant patterns here, e.g. `... OR match(user_key, "^svc[_.-]")`, and the same to RISK-001; remove `root` if root logins are individually attributable |
| `hdsi_rba_ai_user_critical_risk_threshold_exceeded_min_detections` | `1` | Distinct HDSI AI detections required. Read the hand-off note before raising it |
| `hdsi_rba_ai_user_critical_risk_threshold_exceeded_customizations` | `search *` | Post-threshold hook (fields listed in How it works), e.g. `search NOT user_key IN ("breakglass*")`. Filter rows only; keep `user_key`, which RISK-001 reads from this rule's notables |
| `ai_detection_config` row `high_risk_threshold` (common lookup) | `90` | The critical band boundary, shared with RISK-001 |

### Threshold
The default of 90 needs at least two contributing detection events: per-event HDSI AI scores are capped at 30 to 80, and most detections suppress per user for 24 hours. Typical paths to 90 are three or more user detections in one day (for example unsanctioned web access 15 + first-seen provider 20 + high-volume upload 45 + after-hours 10), or a repeated high-severity detection (assisted lateral movement, 50 to 70, suppressed for one hour per user and host). After the HDSI AI detections have run for two weeks, measure the daily user totals and set `high_risk_threshold` near the 99th to 99.5th percentile of users with any AI risk, keeping `medium_risk_threshold` below it:

```spl
`hdsi_rba_ai_user_critical_risk_threshold_exceeded_risk_index` risk_object_type="user" source="* - HDSI AI * - Rule" NOT source="* - HDSI AI Health * - Rule"
| `hdsi_rba_ai_user_critical_risk_threshold_exceeded_user_key`
| where len(user_key)>0 AND NOT (`hdsi_rba_ai_user_critical_risk_threshold_exceeded_excluded_accounts`)
| bin _time span=1d
| stats sum(risk_score) as total_risk dc(source) as detections by _time user_key
| stats count as user_days perc90(total_risk) as p90 perc99(total_risk) as p99 perc99.5(total_risk) as p995 max(total_risk) as max
    count(eval(total_risk>=60)) as ge60 count(eval(total_risk>=90)) as ge90
```

Run it over 14 days. `ge90 / 14` is the expected number of notables a day from this rule.

### Known false positives / Limitations
- **Not testable before the detections run.** None of the HDSI AI detections are deployed in the validation tenants, so `index=risk` holds no HDSI AI events and every real run returns 0 rows. The logic was proven on synthetic risk events (below) and on the tenants' real non-AI risk events with the AI membership filter removed.
- **Volume depends on which detections are enabled.** User-scoring web detections (unsanctioned access, first seen, burst, multiple services, upload, after hours) tend to fire together for one person's first heavy week of a new AI tool. Approve sanctioned tools in `ai_sanctioned_entities` before enabling this rule, or most early notables will be about that.
- **Identity merge collisions.** Two different people with the same account name in different email domains or forests are added together. Generic shared names that are not on the exclusion list (for example a `kiosk` or `shared_operator` account used on many machines) are merged too; add them to `..._excluded_accounts` (in both rules) if they appear. Built-in local accounts are kept per host or domain, and unqualified built-ins are dropped, so they cannot add up across the fleet. Use the alternative `..._user_key` definition in such tenants. Forms that do not share a local part (`john.smith@example.com` and `jsmith`) are not merged; ES identity correlation does not merge them either (`normalized_risk_object` equalled `risk_object` on 100% of user risk events in all 4 tenants).
- **Domain built-in accounts in two forms.** A domain built-in such as `EXAMPLE\Administrator` gets the key `example/administrator`, but the same account scored as `administrator@example.com` keeps the UPN as its key, so its risk is split across two keys and may stay below the threshold. The shipped key is kept because RISK-001 must use the same key. If your detections score domain built-ins in both forms, replace `..._user_key` in **both** packages with this version, which turns `name@domain.tld` built-ins into `domain/name` (tested on all 4 tenants with `makeresults`: `EXAMPLE\Administrator` and `Administrator@example.com` both give `example/administrator`, `WKS01\Administrator` stays `wks01/administrator`, `jdoe@example.com` stays `jdoe`). It assumes the NetBIOS domain name equals the first DNS label:

  ```spl
  eval user_key=lower(trim(risk_object)), user_key=if(match(user_key, "^([^\x5c@]+\x5c)?(administrator|admin|guest|defaultaccount|wdagutilityaccount)(@.+)?$"), replace(replace(user_key, "^([^\x5c@]+)@([^.]+).*$", "\2/\1"), "\x5c", "/"), replace(replace(user_key, "@.*$", ""), "^.*\x5c", ""))
  ```
- **Service and automation accounts are scored like people.** The exclusion list covers OS and built-in identities only. In the all-rule stress test (24 hours, AI filter removed), keys that look like service accounts (`svc` prefix or suffix) were 2 of 104 keys at or above 90 on Tenant A, 0 of 16 on B, 5 of 19 on C and none on D, and the top key on Tenants A and C was an automation account with about 10,000 points. Those totals came from non-AI rules, but once AI endpoint or CLI detections run under automation accounts they will be the first critical notables. They are not excluded by default, because an automation account running AI agents or CLIs is itself worth investigating. Review them before enablement (Deployment step 3).
- **Rolling window edge.** The window is the last 24 hours at each run. A user whose total drops back below the threshold and rises again within the 24-hour suppression gets no second notable; the ES risk timeline still shows it.
- **Suppressed risk events are counted.** The rule does not filter `tag="risk_suppression"`. In validation, `NOT tag="risk_suppression"` made the whole search return 0 events on Tenant A (a broken `notable_suppression-*` event type, which aborts tag evaluation) and on Tenant D (the tag does not exist). A user whose AI risk you have suppressed in ES can therefore still reach this rule; exclude them with `..._filter` or `..._customizations`.
- **Risk factors.** `risk_score` is summed as stored, so ES risk factors (for example a privileged-user multiplier) already applied by ES count toward the threshold. In all 4 tenants the Risk data model's `calculated_risk_score` total was within 0.01% of the `risk_score` total.

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09. The search and all 3 drilldowns parse on all tenants. No FATAL or ERROR messages.

| Tenant | Risk index (24 h, all rules) | HDSI AI user risk | v1.0 rows (24 h) | v1.1 rows (24 h / 7 d) | v1.1 runtime | Notes |
|---|---|---|---|---|---|---|
| A | about 48,000 events, 41,000 user events from scheduled rules | none (not deployed) | 0 | 0 / 0 | 6 to 7 s | Real-shape run (all rules, AI filter removed): 105 users at or above 90, 5 of them combining more than one form of the account, none of them a built-in or service account (before the built-in handling: 108, including `guest`, `system` and `administrator` pseudo-users) |
| B | about 52,000 events, 52,000 user events | none | 0 | 0 / 0 | 1.5 s | Real-shape run: 16 users at or above 90. 357 masked `*****` user events a day are dropped |
| C | about 22,000 events, 8,800 user events | none | 0 | 0 / 0 | 2.5 s | Real-shape run: 19 users at or above 90, 6 of them combining more than one form. Heaviest mix of forms (about 380 of about 1,200 users at 60 to 89 points had more than one) |
| D | 4 events | none | 0 | 0 / 0 | 1 to 2 s | Real-shape run: no user reaches 90 |

Synthetic test (`makeresults` events shaped like `index=risk` rows, run through the full pipeline on all 4 tenants, identical results everywhere):

| Case | Input | Result |
|---|---|---|
| One person in three forms | `alice@example.com` 15 (recon), `EXAMPLE\alice` 30 (execution), `Alice` 45 (exfiltration) | **Notable**: `user=Alice`, `user_key=alice`, total 90, 3 detections, phases `execution, exfiltration, recon`, contributors sorted 45/30/15, technique `T1567` |
| Repeated lateral movement | `frank` 50 + 50, same detection | **Notable**: total 100, 1 detection, 2 events, `T1021.004` |
| Cloned detection | non-standard stanza name, `detection_id=hdsi_ai_mcp_server_execution`, 95 | **Notable** |
| Built-in admin on one host | `WKS03\Administrator` 50 + `WKS03\administrator` 45, two detections | **Notable**: `user_key=wks03/administrator`, total 95 |
| Built-in admin on two hosts | `WKS01\Administrator` 50, `WKS02\Administrator` 50 | No notable (two keys of 50) |
| Built-in guest in two domains | `guest@a.example` 50, `guest@b.example` 50 | No notable (two keys of 50) |
| Unqualified built-in | `Administrator` 60 + `administrator` 60 | Dropped |
| Service and shared accounts | `NT AUTHORITY\SYSTEM` 60 + `SYSTEM` 60, `root` 100, `NT AUTHORITY\NETWORK SERVICE` 100, `IIS APPPOOL\DefaultAppPool` 100 | Dropped |
| Health check with risk turned on | `Audit - HDSI AI Health Data Model Availability - Rule` 100 + AI 10 on `ivan` | No notable (AI total 10) |
| 60 to 89 points | `bob` 30 + 40 = 70; `hank` 60 + 29 = 89 | No notable from this rule (medium band; RISK-001 fires on these only with 2 or more detections) |
| Placeholders and machines | `unknown`/`Unknown` 160, `-` 50, `*****` 100, `NONE` 100, empty 200, `WKS01$` 120 | Dropped |
| Not HDSI AI user risk | aggregator event 100 + AI 20; brute-force rule 90 + AI 10; DNS system object 100 | No notable (AI totals 20 and 10; system ignored) |
| `..._min_detections` = 2 | same input | Only `alice` and `wks03/administrator` |

Expected volume once the user-scoring HDSI AI detections are enabled (estimate from the per-detection scores and the data each tenant holds): Tenant A 0 to 2 notables a day (endpoint and email detections only; no AI web traffic in its Web data), Tenant B 0 (its Web data is inbound and its AI signal is DNS, which scores hosts), Tenant C 1 to 5 (SSE web detections score UPNs), Tenant D 0.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:

1. Enable and validate the user-scoring HDSI AI detections first, and load sanctioned AI use into `ai_sanctioned_entities`.
2. After two weeks of detection data, run the Threshold SPL and set `high_risk_threshold` (and `medium_risk_threshold`) in `ai_detection_config`.
3. Check which service and automation accounts would cross the threshold. Run this over the last 7 days and decide, account by account, whether AI activity under it should raise a notable:

   ```spl
   `hdsi_rba_ai_user_critical_risk_threshold_exceeded_risk_index` risk_object_type="user" source="* - HDSI AI * - Rule" NOT source="* - HDSI AI Health * - Rule"
   | `hdsi_rba_ai_user_critical_risk_threshold_exceeded_user_key`
   | where len(user_key)>0 AND NOT (`hdsi_rba_ai_user_critical_risk_threshold_exceeded_excluded_accounts`)
   | bin _time span=1d
   | stats sum(risk_score) as total_risk dc(source) as detections values(source) as sources by _time user_key
   | where total_risk>=90 AND match(user_key, "svc|service|automation|bot|batch")
   | stats count as days_at_or_above_90 max(total_risk) as max_total values(sources) as sources by user_key
   ```

   For the ones that should not, add a pattern to `..._excluded_accounts` in this package **and** in RISK-001 (for example `OR match(user_key, "^svc[_.-]")`).
4. Keep the hand-off contract (see Band hand-off): identical shared macros in both packages, this stanza name, and `user_key` in the notable. Enable the two rules together.
5. Run the search once over its scheduled window (`-24h@m` to `now`) and review the notables and drilldowns.

The rule creates a high notable and writes no risk. Enabling it is a separately approved change.
