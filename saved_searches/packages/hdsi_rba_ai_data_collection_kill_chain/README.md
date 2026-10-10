## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This risk aggregator raises a **high-severity notable** when one person stages data and then moves it into an AI service. It looks for an HDSI AI *data-collection* detection followed within 4 hours by an HDSI AI *upload/exfiltration* detection for the same user. Examples of collection are a clipboard copy from a business app pasted into AI, a file-access spike before AI use, or an AI capture/page-reader browser extension. Examples of upload are a high-volume upload, a DLP match on an AI upload, personal email plus AI upload, extension bulk transmission, or model-file publish. Each signal alone is common; the ordered pair is the insider-exfiltration pattern. The rule reads `index=risk`, creates a notable (`threat` domain), and writes **no** risk.

v1.0 matched any collection and any upload risk in the same 4-hour bucket, in either order. It accumulated risk on the literal user `unknown`, which ES already holds in three of the four validation tenants from other rules. It treated `DOMAIN\jdoe`, `jdoe@corp` and `jdoe` as three different people, so chains that span endpoint and network data never joined. It annotated MITRE `T1078` and read its window from a shared CSV. v1.1 enforces order, normalises user identities, drops placeholder objects, adds a host-only path without duplicating user notables, and moves every tunable number into a package macro.

### Prerequisites
- **ES risk index** (`index=risk`) populated by the HDSI AI detections. The rule keys on fields that every v1.1 HDSI AI detection writes into its risk events: `detection_id`, `risk_object`, `risk_object_type`, `risk_score`, `search_name`, `user` and `provider`. It does **not** depend on `search_name` text patterns.
- **Contributing detections.** At least one detection from each list must be enabled, otherwise the rule can never fire:

| Phase | Detection (`detection_id`) | Deployment type |
|---|---|---|
| Collection | `Endpoint - HDSI AI Copy-Paste Correlation To AI Service - Rule` (`hdsi_ai_copy_paste_correlation_to_ai_service`) | adhoc (needs browser/endpoint clipboard telemetry) |
| Collection | `Endpoint - HDSI AI Usage Following Data Access Spike - Rule` (`hdsi_ai_usage_following_data_access_spike`) | global |
| Collection | `Network - HDSI AI Browser Extension Activity - Rule` (`hdsi_ai_browser_extension_activity`) | global |
| Upload | `Network - HDSI AI High Volume Upload To AI Service - Rule` (`hdsi_ai_high_volume_upload_to_ai_service`) | global |
| Upload | `Network - HDSI AI Gradual Data Exfiltration Via AI - Rule` (`hdsi_ai_gradual_data_exfiltration_via_ai`) | global (weekly) |
| Upload | `Audit - HDSI AI DLP Violation On Service Upload - Rule` (`hdsi_ai_dlp_violation_on_service_upload`) | incubating: not released (needs `DLP` data; see [`saved_searches/incubating/hdsi_ai_dlp_violation_on_service_upload/`](../../incubating/hdsi_ai_dlp_violation_on_service_upload/README.md)) |
| Upload | `Audit - HDSI AI Sanctioned DLP Violation - Rule` (`hdsi_ai_sanctioned_dlp_violation`) | global |
| Upload | `Network - HDSI AI Browser Extension High-Volume Data Transmission - Rule` (`hdsi_ai_browser_extension_high_volume_data_transmission`) | incubating: not released (see [`saved_searches/incubating/hdsi_ai_browser_extension_high_volume_data_transmission/`](../../incubating/hdsi_ai_browser_extension_high_volume_data_transmission/README.md)) |
| Upload | `Network - HDSI AI Personal Email To AI Service Upload Correlation - Rule` (`hdsi_ai_personal_email_to_ai_service_upload_correlation`) | global |
| Upload | `Threat - HDSI AI Suspicious Model File Exfiltration - Rule` (`hdsi_ai_suspicious_model_file_exfiltration`) | global |

- The drilldowns use the ES `Risk.All_Risk` data model (`| from datamodel:"Risk.All_Risk"`).
- No common macros or lookups are read at search time. The legacy `kill_chain_window_hours` row in `ai_detection_config.csv` is no longer used; the window is the package macro below. `hdsi_ai_rba_common` stays a prerequisite because every contributing detection needs it.

### How it works
- **Base search:** `index=risk`, `risk_object_type` in `..._risk_object_types` (user, system), and `detection_id` in the collection or the upload list. Placeholder objects (`unknown`, `-`, `n/a`, `null`, `none`) are excluded, then `..._filter` is applied.
- **Identity key:** `..._entity_key(2)` lower-cases the risk object, and for users strips a `DOMAIN\` prefix and an `@domain` suffix. Endpoint (`DOMAIN\user`), SSE/proxy (UPN) and firewall (bare name) evidence for one person then correlate. Validation showed that ES leaves `normalized_risk_object` identical to `risk_object` in all tenants, so ES does not do this.
- **No double notables:** a `system` risk event is used only when its contributing row had no attributed user (`user` empty or a placeholder). When a detection scored both the user and the host for one activity, only the user chain is built. Host-only chains still fire for networks without user attribution.
- **Ordering:** events are sorted per entity, collection events are shifted back by `..._order_tolerance_minutes` (60), and `streamstats` carries the most recent collection time forward. An upload is *chained* when it follows a collection by at most `..._window_hours` (4 h). The tolerance absorbs the hourly contributor windows, which can timestamp a collection slightly after the upload it fed. An upload followed hours later by a collection does **not** chain.
- **Output (one row per entity):** `entity`, `entity_type`, `user` or `src`, `collection_signals` (distinct collection detections in 24 h), `exfil_signals` (distinct *chained* upload detections), `chained_exfil_events`, `gap_minutes` (smallest collection-to-upload gap; negative means inside the tolerance), `total_risk` (sum of contributing risk), `providers`, `risk_objects` (raw identities merged), `detection_ids`, `collection_detections`, `exfil_detections`, first/last times. MITRE `T1005`, `T1115`, `T1567`.
- **Schedule:** hourly at minute 35, after all hourly contributors (minutes 5 to 23) have written. It reads the last 24 hours, and suppression is 24 h per `entity_type,entity`, so one chain gives one notable a day.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_rba_ai_data_collection_kill_chain_filter` | `()` | Exclusions inside the risk base search (risk event field names), e.g. `NOT risk_object IN ("svc_backup*")` |
| `hdsi_rba_ai_data_collection_kill_chain_collection_detections` | copy-paste, data-access spike, browser extension activity | `detection_id` list for the collection phase. Must not overlap the upload list |
| `hdsi_rba_ai_data_collection_kill_chain_exfil_detections` | the 7 upload/exfiltration detections above | `detection_id` list for the upload phase. Time-of-day, after-hours and usage-volume anomaly rules are left out because they do not show that data left |
| `hdsi_rba_ai_data_collection_kill_chain_risk_object_types` | `"user","system"` | Set to `"user"` to suppress host-only chains |
| `hdsi_rba_ai_data_collection_kill_chain_window_hours` | `4` | Maximum collection-to-upload gap. Values above 23 have no effect (24 h dispatch) |
| `hdsi_rba_ai_data_collection_kill_chain_order_tolerance_minutes` | `60` | How far a collection timestamp may trail the upload and still count. `0` gives strict order |
| `hdsi_rba_ai_data_collection_kill_chain_entity_key(2)` | bare lower-case account for users | Replace with `lower($object$)` where the same bare account name exists in several domains |
| `hdsi_rba_ai_data_collection_kill_chain_customizations` | `search *` | Post-correlation filter, e.g. `search total_risk>=60` or `search exfil_signals>=1 collection_signals>=2` |

Detections deliberately **not** in either list: `ai_kill_chain_phase` alone is too broad. For example, `Identity - HDSI AI Privileged Account Service Usage` and `Network - HDSI AI Access Via VPN/Proxy Evasion` carry the phase value `collection` but stage no data. That is why the rule uses explicit `detection_id` lists.

### Threshold
The tunable number is the correlation window. After the contributors have run for at least a week, measure the real collection-to-upload gap and set `..._window_hours` just above its p90 (minimum 1, maximum 23):

```spl
index=risk earliest=-7d risk_object_type=user detection_id IN ("hdsi_ai_copy_paste_correlation_to_ai_service","hdsi_ai_usage_following_data_access_spike","hdsi_ai_browser_extension_activity","hdsi_ai_high_volume_upload_to_ai_service","hdsi_ai_gradual_data_exfiltration_via_ai","hdsi_ai_dlp_violation_on_service_upload","hdsi_ai_sanctioned_dlp_violation","hdsi_ai_browser_extension_high_volume_data_transmission","hdsi_ai_personal_email_to_ai_service_upload_correlation","hdsi_ai_suspicious_model_file_exfiltration") NOT risk_object IN ("unknown","-")
| eval k=lower(replace(replace(risk_object,"^.*\x5c",""),"@.*","")), phase=if(match(detection_id,"copy_paste|data_access_spike|browser_extension_activity"),"c","e"), ct=if(phase="c",_time,null())
| sort 0 k _time | streamstats last(ct) as prev by k
| where phase="e" AND isnotnull(prev) | eval gap_h=round((_time-prev)/3600,1)
| stats count perc50(gap_h) as p50 perc90(gap_h) as p90 max(gap_h) as max
```

### Known false positives / Limitations
- **Legitimate AI-assisted work.** A user who copies from a business app into an approved AI assistant and then uploads a large document produces a real chain. Approve the provider pair in `ai_sanctioned_entities` (common): the contributors then stop scoring, and this rule stops with them. Use `..._customizations` only for entity-specific exceptions.
- **AI browser extensions** (collection) are common and low weight. A user with a capture or page-reader extension who also triggers a high-volume upload chains on every upload. If the extension population is large, remove `hdsi_ai_browser_extension_activity` from the collection list.
- **Weekly gradual exfiltration** writes one risk event per week. It chains only when a collection signal lands within the window before that event, so treat it as a bonus contributor.
- **Cross-type correlation is not done.** A user-scored collection followed by a host-only upload (no user on the firewall session) does not chain. Joining host to user would need asset/identity ownership data that the tenants do not populate consistently.
- **Bare-name merge.** Two different people with the same account name in different domains (`A\jdoe`, `B\jdoe`) are merged; see the entity key macro.
- **Risk event timing.** Contributors stamp risk events with the activity time or with the search time. Validation measured up to roughly an hour of difference between the two, which is why the 60-minute tolerance exists.

### Validation
Read-only runs on 2026-10-09 against 4 production ES tenants. None of the HDSI AI detections are deployed there, so `index=risk` holds no HDSI AI events. The logic was proven with synthetic risk events, and the real runs confirm that the search parses and completes.

| Check | Tenant A | Tenant B | Tenant C | Tenant D |
|---|---|---|---|---|
| HDSI AI risk events in `index=risk` (7 d) | 0 | 0 | 0 | 0 |
| Search + 2 drilldowns parse | OK | OK | OK | OK |
| Scheduled window (-24h) rows / runtime | 0 / 6 s | 0 / 2 s | 0 / 3 s | 0 / 2 s |
| 7-day window rows | 0 | 0 | 0 | 0 |
| `unknown` user risk objects from other rules (24 h) | present | present | present (about 130 events) | none |
| User risk object formats in use | bare, UPN, `DOMAIN\user` | bare, UPN, `DOMAIN\user` | bare, UPN, `DOMAIN\user` | bare |
| `normalized_risk_object` differs from `risk_object` | never | never | never | never |

Synthetic test: 22 `makeresults format=csv` risk events covering 10 scenarios, run through the full pipeline. Exactly the 4 expected entities fired:
- mixed `DOMAIN\user` and UPN identities merged: gap 60 min;
- collection 30 min after the upload, inside the tolerance: gap -30;
- the most recent of two collections chained to an upload: gap 30 min, with an earlier unchained upload correctly not counted;
- a host-only chain with case-different host names merged.

Correctly suppressed:
- upload before collection (4 h apart);
- a gap of 9 h, beyond the window;
- the `unknown` user;
- a system event whose row had a user;
- collection only, and upload only;
- a non-listed DNS detection, which did not count.

### Deployment
The package ships with `enable_alerting: false`. Before enablement, confirm that at least one collection and one upload detection are enabled and writing risk events with `detection_id`. Run the Threshold SPL after a week to set the window, and review a week of would-be notables with the search run ad hoc. This rule creates notables only (`action.notable = 1`, `action.risk = 0`), so it adds no RBA score. Enabling it, and retiring any rule it replaces, must be one separately approved change.
