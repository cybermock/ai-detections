# AI-RISK-003 - HDSI RBA AI Data Collection Kill Chain

> **Detection ID:** AI-RISK-003
> **Package:** `hdsi_rba_ai_data_collection_kill_chain` (v1.1.0, `deployment_type: global`)
> **Correlation search:** `Threat - HDSI RBA AI Data Collection Kill Chain - Rule`
> **Status:** Active (ships with `enable_alerting: false`; enabling is a separately approved change)
> **Type:** Risk aggregator. Creates a notable (`action.notable = 1`), writes **no** risk (`action.risk = 0`)
> **Notable:** severity `high`, security domain `threat`, title `AI Kill Chain - Data Collection to AI Upload (<entity>)`
> **Risk Score:** N/A. The `_risk` entry (user, 60) is kept for conformance only; with `action.risk = 0` nothing is written to the risk index
> **MITRE ATT&CK:** T1005 Data from Local System, T1115 Clipboard Data (Collection); T1567 Exfiltration Over Web Service (Exfiltration)
> **Data Source:** ES risk index (`index=risk`); drilldowns use the `Risk.All_Risk` data model
> **Schedule:** `35 * * * *` (hourly at minute 35, after the hourly contributors have written)
> **Lookback Window:** `-24h@m` to `now`
> **Suppression:** 24 hours (`86400s`) per `entity_type,entity`
> **Kill Chain Phase:** Collection followed by exfiltration (`ai_kill_chain_phase="exfiltration"` on the notable)
> **Last Updated:** 2026-10-09

---

## Overview

This rule raises a high notable when one person stages data and then moves it into an AI service. It looks for an HDSI AI **data-collection** detection followed, within 4 hours, by an HDSI AI **upload or exfiltration** detection for the same user (or for the same host when no user is attributed). A collection signal on its own is common: a clipboard paste into an AI assistant, a burst of file access before AI use, or an AI page-reader extension. An upload signal on its own is common too. The ordered pair is the insider-exfiltration pattern: gather business data, then push it out through an AI service.

The typical actor is an insider moving data to an AI tool outside policy, or a compromised account doing the same. The business risk is loss of confidential data to a third-party model provider, with no DLP control in the path.

The rule only reads risk events that the HDSI AI detections have already written. It adds no risk score of its own, so it never inflates a user's RBA total; it promotes a specific sequence to the SOC queue.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Technique ID | T1005, T1115, T1567 (`action.correlationsearch.annotations`, mirrored in the `mitre_attack` result field) |
| Technique Name | Data from Local System; Clipboard Data; Exfiltration Over Web Service |
| Tactic | Collection (T1005, T1115); Exfiltration (T1567) |
| Sub-technique | N/A. The contributing upload rules carry their own sub-techniques in their risk events |

---

## Detection Logic

### Plain English

1. Read 24 hours of `index=risk` for `user` and `system` risk objects whose `detection_id` is in the collection list or the upload list (see below). Placeholder objects (`unknown`, `-`, `n/a`, `null`, `none`) are dropped, then the tenant filter macro is applied.
2. Build one identity key per entity. For users the key is the lower-case account with any `DOMAIN\` prefix and `@domain` suffix removed, so `CORP\jdoe`, `jdoe@corp.example` and `jdoe` are one person. Systems are keyed on the lower-case host value.
3. Use a `system` risk event only when its row had no attributed user. When a detection scored both the user and the host for one activity, only the user chain is built, so one activity never produces two notables.
4. Sort each entity's events by time. Collection events are shifted back by the order tolerance (60 minutes) so that hourly contributors that stamp the same activity into different buckets still count. `streamstats` carries the latest collection time forward.
5. An upload event is **chained** when it follows a collection event by no more than the window (4 hours). An upload that happened before the collection (outside the tolerance) does not chain.
6. Keep entities with at least one chained upload, at least one distinct collection detection and at least one distinct chained upload detection.
7. Emit one row per entity with the counts, the smallest gap, the total contributing risk, the providers and the detection names. Suppress for 24 hours per entity.

**Collection list** (`hdsi_rba_ai_data_collection_kill_chain_collection_detections`):

| detection_id | Correlation search | Runbook | Deployment type |
|---|---|---|---|
| `hdsi_ai_copy_paste_correlation_to_ai_service` | `Endpoint - HDSI AI Copy-Paste Correlation To AI Service - Rule` | AI-025 | **adhoc** (needs clipboard telemetry) |
| `hdsi_ai_usage_following_data_access_spike` | `Endpoint - HDSI AI Usage Following Data Access Spike - Rule` | AI-043 | global |
| `hdsi_ai_browser_extension_activity` | `Network - HDSI AI Browser Extension Activity - Rule` | AI-021 | global |

**Upload list** (`hdsi_rba_ai_data_collection_kill_chain_exfil_detections`):

| detection_id | Correlation search | Runbook | Deployment type |
|---|---|---|---|
| `hdsi_ai_high_volume_upload_to_ai_service` | `Network - HDSI AI High Volume Upload To AI Service - Rule` | AI-007 | global |
| `hdsi_ai_gradual_data_exfiltration_via_ai` | `Network - HDSI AI Gradual Data Exfiltration Via AI - Rule` | AI-044 | global (weekly) |
| `hdsi_ai_dlp_violation_on_service_upload` | `Audit - HDSI AI DLP Violation On Service Upload - Rule` | AI-020 | **incubating** (not released; needs the CIM `DLP` model; see [`saved_searches/incubating/hdsi_ai_dlp_violation_on_service_upload/`](../../saved_searches/incubating/hdsi_ai_dlp_violation_on_service_upload/RUNBOOK.md)) |
| `hdsi_ai_sanctioned_dlp_violation` | `Audit - HDSI AI Sanctioned DLP Violation - Rule` | AI-038 | global |
| `hdsi_ai_browser_extension_high_volume_data_transmission` | `Network - HDSI AI Browser Extension High-Volume Data Transmission - Rule` | AI-024 | **incubating** (not released; see [`saved_searches/incubating/hdsi_ai_browser_extension_high_volume_data_transmission/`](../../saved_searches/incubating/hdsi_ai_browser_extension_high_volume_data_transmission/RUNBOOK.md)) |
| `hdsi_ai_personal_email_to_ai_service_upload_correlation` | `Network - HDSI AI Personal Email To AI Service Upload Correlation - Rule` | AI-027 | global |
| `hdsi_ai_suspicious_model_file_exfiltration` | `Threat - HDSI AI Suspicious Model File Exfiltration - Rule` | AI-032 | global |

Time-of-day, after-hours and usage-volume anomaly rules are deliberately not in the upload list: they show that AI was used, not that data left. Privileged Account Service Usage and Access Via VPN/Proxy Evasion are not in the collection list either, even though some versions labelled them `collection`; they stage no data.

### Key Fields

| Field | Description | Example Value |
|---|---|---|
| `entity` | Normalised identity key (bare lower-case account, or lower-case host) | `jdoe` |
| `entity_type` | `user` or `system` | `user` |
| `user` / `src` | Set from `entity` for users / systems | `jdoe` |
| `collection_signals` | Distinct collection detections in 24 h | `1` |
| `exfil_signals` | Distinct upload detections that chained to a collection | `2` |
| `chained_exfil_events` | Upload risk events that chained | `3` |
| `gap_minutes` | Smallest collection-to-upload gap. A negative value means the collection was stamped after the upload but inside the 60-minute tolerance | `35` |
| `first_collection_time` / `first_chained_exfil_time` | When the chain started and when the first chained upload happened | `10/09/2026 09:12:00` |
| `total_risk` | Sum of the contributing risk scores (all listed detections, 24 h) | `95` |
| `providers` | AI providers named on the contributing risk events | `OpenAI` |
| `risk_objects` | Every raw identity form merged into `entity` | `CORP\jdoe`, `jdoe@corp.example` |
| `collection_detections` / `exfil_detections` / `detections` | Contributing correlation search names | `Endpoint - HDSI AI Usage Following Data Access Spike - Rule` |
| `detection_ids` | `detection_id` values seen | `hdsi_ai_high_volume_upload_to_ai_service` |

### Thresholds

| Parameter | Default Value | Macro | Notes |
|---|---|---|---|
| Correlation window | `4` hours | `hdsi_rba_ai_data_collection_kill_chain_window_hours` | Maximum gap from the most recent collection to the upload. Values above 23 have no effect (24 h dispatch) |
| Order tolerance | `60` minutes | `hdsi_rba_ai_data_collection_kill_chain_order_tolerance_minutes` | How far a collection timestamp may trail the upload and still count. `0` = strict order |
| Risk object types | `"user","system"` | `hdsi_rba_ai_data_collection_kill_chain_risk_object_types` | Set to `"user"` to drop host-only chains |
| Minimum signals | 1 collection + 1 chained upload | (in SPL) | Raise through `..._customizations`, e.g. `search collection_signals>=2` |

The rule no longer reads `kill_chain_window_hours` from `ai_detection_config`; the window is the package macro.

---

## Triage Steps

> **Estimated triage time:** 20-40 minutes

Replace `$entity$` with the `entity` value from the notable (already lower case, no domain). Run each search over the notable's window (the drilldowns use `$info_min_time$` to `$info_max_time$`), or over the last 24 hours.

The `tstats summariesonly=t` evidence searches read accelerated summaries only. In validation the most recent 15-30 minutes were not yet summarised on two tenants, so for very recent activity re-run them later, or with `summariesonly=f` over a short window.

### Step 1: Validate the notable

```spl
index=notable source="Threat - HDSI RBA AI Data Collection Kill Chain - Rule" earliest=-7d
| search entity="$entity$"
| table _time, entity, entity_type, risk_objects, collection_signals, exfil_signals, chained_exfil_events, gap_minutes, first_collection_time, first_chained_exfil_time, total_risk, providers, detections
```

- Confirm `entity` is a real person (or a real host for `entity_type=system`), not a service, kiosk or shared account.
- Check `risk_objects`: if it lists two different people who share a bare account name in different domains (`A\jdoe`, `B\jdoe`), treat the chain as two separate cases (see the entity key limitation below).
- A repeat notable for the same entity on consecutive days is a pattern, not a duplicate.

### Step 2: Rebuild the chain timeline

This is the first drilldown (`View AI risk events behind the chain`) with the phase added.

```spl
| from datamodel:"Risk.All_Risk"
| search detection_id IN (`hdsi_rba_ai_data_collection_kill_chain_collection_detections`) OR detection_id IN (`hdsi_rba_ai_data_collection_kill_chain_exfil_detections`)
| eval entity_key=`hdsi_rba_ai_data_collection_kill_chain_entity_key(risk_object, risk_object_type)`
| search entity_key="$entity$"
| eval kc_phase=if(in(detection_id, `hdsi_rba_ai_data_collection_kill_chain_collection_detections`), "collection", "upload")
| table _time, kc_phase, source, detection_id, risk_object, risk_object_type, risk_score, provider, risk_message
| sort 0 _time
```

- Read it top to bottom: what was collected (clipboard source app, file-access spike, extension), and what was uploaded next (provider, volume, DLP match, model file).
- Note the provider on the upload. A sanctioned enterprise tenant of the provider is a very different case from a personal account on a consumer site.
- Use the second drilldown (`Summarize AI risk composition`) for a per-detection count when the timeline is long.

### Step 3: Review the raw upload evidence

For web or SSE uploads (the detection names a provider domain or SSE app). The `fillnull_value` keeps rows where only one of `url_domain` / `site` is mapped: some SSE products put the app name in `site` and leave `url_domain` empty.

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count sum(Web.bytes_out) as bytes_out values(Web.http_method) as http_method min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url_domain=* OR Web.site=*) Web.bytes_out>0 Web.user="*$entity$*" by Web.user Web.src Web.url_domain Web.site
| rename Web.* as *
| eval ai_domain=lower(coalesce(nullif(url_domain,"unknown"), nullif(site,"unknown"))), ai_input_type=if(isnull(nullif(url_domain,"unknown")), "app", "host")
| `ai_domains_filter`
| eval mb_out=round(bytes_out/1024/1024, 2)
| convert ctime(firstTime) ctime(lastTime)
| sort - mb_out
| table firstTime, lastTime, user, src, ai_domain, provider, ai_match, count, mb_out, http_method
```

For firewall-observed uploads (App-ID based, no proxy):

```spl
| tstats summariesonly=t allow_old_summaries=t count sum(All_Traffic.bytes_out) as bytes_out values(All_Traffic.dest) as dest min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.bytes_out>0 All_Traffic.user="*$entity$*" by All_Traffic.src All_Traffic.user All_Traffic.app
| rename All_Traffic.* as *
| eval mb_out=round(bytes_out/1024/1024, 2)
| convert ctime(firstTime) ctime(lastTime)
| sort - mb_out
| head 25
```

- Look for uploads (POST/PUT, large `bytes_out`) to the provider in the chain, close in time to the collection.
- For an `entity_type=system` chain, replace the `user` filter with `Web.src="$entity$"` / `All_Traffic.src="$entity$"`.

### Step 4: Review the collection evidence on the endpoint

```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where Processes.user="*$entity$*" by Processes.dest Processes.user Processes.process_name
| rename Processes.* as *
| eval process_name_lc=lower(process_name)
| `ai_process_enrich`
| where enabled=1 OR match(process_name_lc, "(?i)7z|winrar|zip|robocopy|xcopy|rclone")
| convert ctime(firstTime) ctime(lastTime)
| table firstTime, lastTime, dest, user, process_name, tool, provider, count, process
```

- Did the user run AI tools or archive/copy tools on the host where the collection fired?
- For a file-access spike, open the contributing detection's own drilldowns (AI-043) to see which shares or files were read.

### Step 5: Identify the user and check for other risk

```spl
| inputlookup identity_lookup_expanded
| search identity="$entity$"
| table identity, first, last, email, managedBy, bunit, category, priority, watchlist, endDate
```

```spl
| from datamodel:"Risk.All_Risk"
| search risk_object_type="user" risk_object="*$entity$*"
| eval family=if(match(source, " - HDSI (RBA )?AI "), "HDSI AI", "other")
| stats count as risk_events sum(risk_score) as total_risk values(risk_object) as risk_objects by family source
| sort - total_risk
```

- Departing employees (`endDate` near), users on a watchlist, and users in finance, legal, HR or R&D raise the priority.
- Check whether the same user also has a Multi-Vector (AI-RISK-005), Privilege Escalation (AI-RISK-004) or user threshold (AI-RISK-001/002) notable.

### Step 6: Determine sanctioned status

```spl
| inputlookup ai_sanctioned_entities
| search entity="*$entity$*" OR entity="*"
| table entity_type, entity, provider, scope, expires, owner, reason, enabled, allow_key
```

- An active entry for the user (or their group, or the provider organisation-wide) means the contributing detections should have stopped scoring. If they still scored, check the entry's `enabled` and `expires` values.
- Approved use of a provider does not approve moving restricted data into it. A sanctioned provider can still be a true positive when the data is restricted.

### Step 7: Make a determination

- **True Positive:** business data was collected and then sent to an AI service outside policy (wrong provider, personal account, restricted data, or a departing user).
- **Benign True Positive:** the sequence is real and the workflow is approved (an approved AI assistant on an enterprise tenant, non-sensitive data).
- **False Positive:** the two signals are unrelated (for example an AI capture extension that is always on, followed by an unrelated upload), or two different people were merged by the identity key.

---

## True Positive Indicators

- The upload provider is unsanctioned, or is reached with a personal account or from an unmanaged device.
- The collection touched sources the user does not normally use (a data-access spike on shares outside their role).
- Upload volume is large compared with the user's normal AI use, or a DLP rule matched the upload.
- The user is leaving, is on a watchlist, or recently gained privileges (see AI-RISK-004).
- The same chain repeats on several days, or `gap_minutes` is short and consistent (copy then upload, again and again).

---

## False Positive Scenarios

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Approved AI-assisted work: copying from a business app into an approved assistant, then uploading a document | Medium | Add the user, group or provider to `ai_sanctioned_entities`; the contributors stop scoring and this rule stops with them |
| A large population with an AI capture or page-reader extension: every upload by those users chains | Medium | Remove `hdsi_ai_browser_extension_activity` from `..._collection_detections`, or exclude the extension's users in `..._filter` |
| Two different people with the same bare account name in two domains are merged | Low | Change `..._entity_key(2)` to `lower($object$)` in multi-domain tenants |
| Contributor timing: an hourly contributor stamps the collection after the upload it fed | Low | Already absorbed by the 60-minute tolerance; set `..._order_tolerance_minutes` to `0` only if strict order is required |

---

## Response Actions

### If confirmed True Positive

1. **Contain:** block the user's access to the AI provider at the proxy, SSE or firewall, and revoke any personal-account OAuth grants the user made to the provider. If an endpoint was used, consider isolating it.
2. **Notify:** the user's manager, data governance or privacy, and legal if regulated data is involved.
3. **Investigate:** determine what data was collected and uploaded (file names from the endpoint, DLP match details, upload size). Request the provider's enterprise audit log if the tenant is corporate.
4. **Remediate:** request deletion from the provider where possible, rotate any credentials or keys that were in the data, and enforce DLP on the AI upload path.
5. **Document:** record the timeline from Step 2 and the evidence from Steps 3-4 in the case.

### If Benign True Positive

1. Add the user, group or provider to `ai_sanctioned_entities` (common package) with a scope and an `expires` date.
2. Record the business justification in `reason`.
3. Close the notable as Benign True Positive.

---

## Tuning Guidance

### Reducing false positives

- Prefer sanctioning at the source (`ai_sanctioned_entities`), which quiets every contributing detection.
- Use `hdsi_rba_ai_data_collection_kill_chain_filter` (inline in the risk base search, risk event field names) for entity exceptions, e.g. `NOT risk_object IN ("svc_backup*")` or `NOT search_name="*Browser Extension Activity*"`.
- Use `hdsi_rba_ai_data_collection_kill_chain_customizations` (after correlation) to raise the bar, e.g. `search total_risk>=60` or `search collection_signals>=2`.
- Keep the collection and upload lists disjoint.

### Adjusting thresholds

After the contributors have run for at least a week, measure the real collection-to-upload gap and set `..._window_hours` just above its p90 (between 1 and 23):

```spl
index=risk earliest=-7d risk_object_type=user detection_id IN ("hdsi_ai_copy_paste_correlation_to_ai_service","hdsi_ai_usage_following_data_access_spike","hdsi_ai_browser_extension_activity","hdsi_ai_high_volume_upload_to_ai_service","hdsi_ai_gradual_data_exfiltration_via_ai","hdsi_ai_dlp_violation_on_service_upload","hdsi_ai_sanctioned_dlp_violation","hdsi_ai_browser_extension_high_volume_data_transmission","hdsi_ai_personal_email_to_ai_service_upload_correlation","hdsi_ai_suspicious_model_file_exfiltration") NOT risk_object IN ("unknown","-")
| eval k=lower(replace(replace(risk_object,"^.*\x5c",""),"@.*","")), phase=if(match(detection_id,"copy_paste|data_access_spike|browser_extension_activity"),"c","e"), ct=if(phase="c",_time,null())
| sort 0 k _time
| streamstats last(ct) as prev by k
| where phase="e" AND isnotnull(prev)
| eval gap_h=round((_time-prev)/3600,1)
| stats count perc50(gap_h) as p50 perc90(gap_h) as p90 max(gap_h) as max
```

### Confirm the contributors write `detection_id`

This rule selects contributors **only** by `detection_id`. Every HDSI AI detection sets it in SPL, and ES copies result fields into the risk event. On the four validation tenants a small number of other rules carried an ES-assigned UUID in `detection_id` instead. After enabling the contributors, confirm their risk events keep the `hdsi_ai_*` value:

```spl
| from datamodel:"Risk.All_Risk"
| search source="* - HDSI AI * - Rule"
| eval id_shape=case(isnull(detection_id), "missing", match(mvindex(detection_id,0), "^hdsi_ai_"), "hdsi_ai", true(), "other")
| stats count by source id_shape
```

If a contributor shows `missing` or `other`, this rule cannot see it. Fix the contributor before relying on this rule.

### Adding allowlist entries

To allowlist a specific user for a specific provider (common lookup `ai_sanctioned_entities`):

```
entity_type,entity,provider,scope,expires,owner,reason,enabled,allow_key
user,<username>,<provider>,provider,<YYYY-MM-DD>,<your_name>,<justification>,1,<username>|<provider_lowercase>
```

---

## Related Detections

| Detection ID | Name | Relationship |
|---|---|---|
| AI-025, AI-043, AI-021 | Copy-Paste Correlation To AI Service; Usage Following Data Access Spike; Browser Extension Activity | Collection-phase contributors |
| AI-007, AI-044, AI-020, AI-038, AI-024, AI-027, AI-032 | High Volume Upload; Gradual Data Exfiltration; DLP Violation On Service Upload; Sanctioned DLP Violation; Browser Extension High-Volume Data Transmission; Personal Email To AI Upload; Suspicious Model File Exfiltration | Upload-phase contributors. AI-020 and AI-024 are incubating (not released) |
| AI-RISK-005 | HDSI RBA AI Multi-Vector Risk | Breadth of AI risk without order; often fires for the same user |
| AI-RISK-004 | HDSI RBA AI Privilege Escalation Correlation | Privilege change followed by AI collection or exfiltration |
| AI-RISK-001 / AI-RISK-002 | HDSI RBA AI User Risk Threshold Exceeded (medium / critical) | Score-based escalation of the same user's AI risk |

---

## Data Requirements

| Requirement | Details |
|---|---|
| Data Model | ES risk index (`index=risk`); `Risk.All_Risk` for drilldowns |
| Required Fields | `detection_id`, `risk_object`, `risk_object_type`, `risk_score`, `search_name`, `user`, `provider` on the contributing risk events |
| Contributors | At least one collection **and** one upload detection enabled with `action.risk = 1`, otherwise the rule can never fire. Three of the ten are adhoc (clipboard telemetry, CIM `DLP`, browser-extension telemetry) |
| Sourcetype Examples | N/A (reads risk events). Contributors need Endpoint (Processes, Filesystem), Web or Network_Traffic, and Email data |
| CIM Compliance | Contributors must map `user` consistently enough for the bare-name key to join endpoint and web evidence |
| Acceleration | Not required for the rule. Triage Steps 3-4 use `tstats summariesonly=t` and need accelerated Web, Network_Traffic and Endpoint models |
| Lookups | None at run time. Triage uses `identity_lookup_expanded`, `ai_sanctioned_entities`, `ai_provider_domains` (via `ai_domains_filter`) and `ai_tool_processes` (via `ai_process_enrich`) |
| Prerequisite package | `hdsi_ai_rba_common` (required by every contributor) |

### Validation (2026-10-09)

Read-only runs against 4 production ES tenants (Splunk Cloud, ES 8.x, labelled Tenant A-D). No HDSI AI detection was deployed there, so `index=risk` held no HDSI AI events and every real run returned 0 rows, as expected.

| Check | Tenant A | Tenant B | Tenant C | Tenant D |
|---|---|---|---|---|
| Search + 2 drilldowns parse | OK | OK | OK | OK |
| Scheduled window rows / runtime | 0 / 6 s | 0 / 2 s | 0 / 3 s | 0 / 2 s |
| `unknown` user risk objects from other rules (24 h) | present | present | present | none |
| User risk object formats in use | bare, UPN, `DOMAIN\user` | bare, UPN, `DOMAIN\user` | bare, UPN, `DOMAIN\user` | bare |

A 22-event synthetic test (10 scenarios) fired exactly the 4 expected chains: mixed `DOMAIN\user` and UPN identities, a collection inside the tolerance, the latest of two collections, and a host-only chain. It suppressed upload-before-collection, a 9-hour gap, the `unknown` user, a system event whose row had a user, single-phase entities and a non-listed DNS detection. Expected volume once contributors run: Tenant A 0-2 notables a day, Tenant C 0-1, Tenants B and D about 0.

---

## Revision History

| Date | Author | Change |
|---|---|---|
| 2026-03-04 | Hurricane Labs | Initial runbook |
| 2026-10-09 | Hurricane Labs | 1.1.0: rewritten for the released package. Stanza renamed to `Threat - HDSI RBA AI Data Collection Kill Chain - Rule`. Explicit `detection_id` phase lists, enforced collection-before-upload order with a 60-minute tolerance, bare-account identity key, host-only path without duplicate notables, placeholder objects dropped, MITRE changed from T1078 to T1005/T1115/T1567, window moved from `ai_detection_config` to package macros, hourly at :35 with 24 h suppression. Notable only, no risk. Triage SPL rebuilt on `Risk.All_Risk`, with `url_domain`/`site` handling |
