## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule detects a user who pastes (or drags) content into an AI service page repeatedly within one hour: 3 or more pastes into the same provider by default. It uses telemetry that records the paste itself, its destination and, where available, where the content came from. Sources are enterprise-browser audit events (Island `Paste`/`Drop` events) and CIM DLP clipboard incidents that name the destination site. Pasting is the main way business text reaches ChatGPT, Gemini, Claude and similar tools, and proxy logs cannot see it. The rule creates risk on `user` and, when the source records a device hostname, on `src` (system). It does not create a notable. MITRE ATT&CK: T1567 (Exfiltration Over Web Service) and T1115 (Clipboard Data). The `ai_kill_chain_phase` is `collection`, as the `hdsi_rba_ai_data_collection_kill_chain` aggregator expects.

The package is **ad hoc** (`deployment_type: adhoc`). Only one of the 4 validation tenants had a data source that records pastes (Island browser audit logs), and no tenant had DLP data. The rule parses and runs cleanly everywhere and returns nothing where the data is absent.

### Prerequisites
At least one of the following is required. The `data_prereqs` searches in `package.yml` check for both.
- **Island Enterprise Browser / Island browser extension audit logs** (sourcetype `island-audits`, JSON). The rule uses the fields `type` (`Paste`, `Drop`), `url` (the page pasted into), `user` / `email`, `details.clipboard_details.clipboard_source_url` (the tab copied from), `verdict_reason` ("…external source" means the content came from outside the browser, for example a desktop application), `details.clipboard_details.browser_element_type`, `verdict`, and `src_nt_host` / `machine_name`. With the browser extension, the device hostname is usually empty. In that case only the user receives risk.
- **CIM `DLP` model, dataset `DLP_Incidents`** (accelerated), from an endpoint or browser DLP product that logs paste/clipboard events. The rule selects incidents whose `action`, `signature`, `dlp_type` or `object_category` contains `paste` or `clipboard`. It keeps an incident only when `dest` (or `object_path`) resolves to an AI provider, so **the DLP product must record the destination site**. Clipboard events without a destination are ignored. The model is named `DLP` (the old rule used `Data_Loss_Prevention`, which does not exist and failed with a FATAL error in every tenant).
- **Other products**: to use another enterprise browser or browser-DLP product, replace `..._paste_events` and `..._normalise` together so they emit the same fields: `user`, `src`, `paste_type`, `paste_url`, `copy_source_url`, `copy_external`, `paste_element`, `paste_verdict`, `paste_product` and `count`.
- **ES identities (optional):** `bunit` comes from `identity_lookup_expanded` and is used for allowlist group keys and `ai_risk_multiplier`.
- **Common package `hdsi_ai_rba_common`:** `ai_domains_filter` (resolves the paste destination with `ai_input_type="host"`), `ai_unsanctioned_filter(user,src,provider)` (allowlist `ai_sanctioned_entities`, keys `user|provider`, `src|provider`, `bunit|provider`, `*` for any provider) and `ai_risk_multiplier`.

### How it works
- **Browser branch.** A raw search for Island events containing `Paste` or `Drop` (`..._paste_events` plus the inline `..._filter`). `..._normalise` keeps `type` Paste/Drop and maps the vendor fields. The source IP fields are never used: for remote users they are home-LAN or public egress addresses that many people share.
- **DLP branch.** An appended `tstats` on `DLP.DLP_Incidents` selects paste/clipboard incidents (`..._dlp_paste_events` and the inline `..._dlp_filter`).
- The paste destination is resolved with `ai_domains_filter`. Rows that are not AI destinations are dropped. `unknown`, `-` and empty users and devices, and IP-shaped `src` values, are set to null. A row needs a user or a device, so no risk object is ever the literal `unknown`.
- **Noise removed before counting:**
  - pastes into the browser Address Bar or Find Bar;
  - pastes copied inside the AI service itself (for example, inside a ChatGPT conversation). A paste counts as same-site only when the copy-source host equals the destination host, is a subdomain of it, or resolves in `ai_provider_domains` to the same provider (exact host, or a parent domain flagged `match_subdomains=1`). The registrable domain is deliberately **not** compared. A paste into Gemini or NotebookLM copied from Gmail, Google Docs, Drive or Chat, or a paste into an M365 Copilot page copied from Outlook or Teams on `cloud.microsoft`, is a cross-application paste and is counted.
- Each paste gets a copy-source class:
  - `business_app`: the copy source matches `..._sensitive_copy_sources`;
  - `other_site`: another web page;
  - `outside_browser`: Island reported an external source;
  - `not_recorded`.
- **Aggregation.** Rows are summed per `user`, `src` and `provider` over the hour. The rule fires when `paste_count >= ..._min_pastes`, after the allowlist.
- **Scoring:**
  - Base 20; 30 when `paste_count` is at least 3× the threshold.
  - +10 when any paste came from a business application or from outside the browser.
  - The base is multiplied by the provider `severity_weight` and by `risk_multiplier`, and halved when every paste was blocked. A paste row counts as blocked only when all of its verdict values are block/deny/prevent. DLP rows are split by `action`, so a mix of allowed and blocked incidents is never counted as fully blocked. The result is floored at 5 and capped at 60, then written to `risk_score`, which ES applies to every risk object in the row.
  - The literal `_risk` scores (user 20, system 10) are only the fallback.
- **Schedule.** Hourly at :22 over `-80m@m` to `-20m@m`. The window is shifted 20 minutes because Island audit events reached Splunk a median of about 6 minutes, and a p95 of about 11 minutes, after the paste. A standard `-65m@m` to `-5m@m` window would miss many of them.
- **Suppression.** 24 h per `user` and `src`. The first hour of repeated pasting is the signal; the aggregators handle accumulation.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_copy_paste_correlation_to_ai_service_paste_events` | `(index=* sourcetype="island-audits" ("Paste" OR "Drop"))` | Browser base search. Set the Island index for speed. Replace it (together with `..._normalise`) for another product. |
| `hdsi_ai_copy_paste_correlation_to_ai_service_filter` | `()` | Exclusions inline in the browser base search (raw Island field names), e.g. `NOT user IN ("svc_*")`. |
| `hdsi_ai_copy_paste_correlation_to_ai_service_normalise` | Island field mapping | Maps vendor fields to the normalised fields listed under Prerequisites. |
| `hdsi_ai_copy_paste_correlation_to_ai_service_dlp_paste_events` | paste/clipboard wildcards | Which DLP incidents count as a paste. Copy-to-USB, network share and print are deliberately not matched. |
| `hdsi_ai_copy_paste_correlation_to_ai_service_dlp_filter` | `()` | Exclusions inline in the DLP `tstats` where clause (`DLP_Incidents.*` names). |
| `hdsi_ai_copy_paste_correlation_to_ai_service_min_pastes` | `3` | Pastes into one provider per user (or device) per hour before the rule fires. |
| `hdsi_ai_copy_paste_correlation_to_ai_service_sensitive_copy_sources` | regex of common business SaaS | Copy-source domains that add 10 points. Add the tenant's EHR, ERP, CRM, wiki and internal application domains. Personal webmail is deliberately absent. Google Workspace tenants should add `mail\\.google\\.com` and `chat\\.google\\.com` (Gmail and Chat share hosts with personal accounts, so they are not shipped). |
| `hdsi_ai_copy_paste_correlation_to_ai_service_customizations` | `search *` | Post-threshold hook. Fields: `user`, `src`, `user_display`, `src_display`, `provider`, `ai_domain_list`, `paste_count`, `blocked_count`, `copy_source_list`, `copy_source_class_list`, `paste_verdict_list`, `paste_product`, `min_pastes`, `base_score`, `severity_weight`, `risk_multiplier`, `risk_score`. |
| `hdsi_ai_copy_paste_correlation_to_ai_service_risk_score` | `search *` | Last pipe. Overrides `risk_score` (max 100) for the row. |

Sanctioned AI tools (for example an enterprise ChatGPT or Copilot tenant) belong in `ai_sanctioned_entities` (`bunit|openai`, `user|*`), not in the filter macro, so that the allowlist stays auditable and can carry an `expires` date.

### Threshold
The default of 3 pastes per user, provider and hour is set from the validation tenant's 7-day profile:
- 459 user-hours had at least one paste into an AI page;
- median 1, p90 5, p99 about 21 pastes per user-hour;
- 116 user-hours (63 users) reached 3 or more.

A threshold of 1 would score almost every AI user every day. Profile 7 days in the target tenant before enabling. **Set the Island index in `..._paste_events` first.** In validation, a 7-day raw search over `index=*` hit the 300 s auto-finalise limit and returned partial counts with no error. If the search still finalises early, run it in 1-day slices (`earliest=-1d@d latest=@d`, then `-2d@d`/`-1d@d`, and so on) and combine the results.

```spl
`hdsi_ai_copy_paste_correlation_to_ai_service_paste_events` earliest=-7d@h latest=@h
| `hdsi_ai_copy_paste_correlation_to_ai_service_normalise`
| eval ai_domain=paste_url, ai_input_type="host" | `ai_domains_filter`
| where NOT match(lower(coalesce(paste_element,"")),"address bar|find bar")
| eval copy_source_domain=replace(lower(replace(replace(copy_source_url,"^[a-z][a-z0-9+.-]*://",""),"[/:?#].*$","")),"^www\\d*\\.","")
| where isnull(copy_source_domain) OR (copy_source_domain!=ai_domain AND NOT like(copy_source_domain,"%.".ai_domain))
| bin _time span=1h | stats count by _time user provider
| stats count as user_hours dc(user) as users perc50(count) as p50 perc90(count) as p90 perc99(count) as p99 max(count) as max
        count(eval(count>=3)) as hours_ge3 dc(eval(if(count>=3,user,null()))) as users_ge3
```

Keep the threshold near p90 (`max(3, p90)`) so the rule scores repeated pasting rather than single prompts. Bulk pasting (3× the threshold) already earns the higher base score.

### Known false positives / Limitations
- **Ordinary AI use.** Pasting into an AI tool is often legitimate. In validation, many copy sources were online-course and learning-management sites (staff coursework) or general web pages. That is why scores are modest (20–40 before multipliers) and the rule is risk-only. Allowlist sanctioned tools and teams in `ai_sanctioned_entities`, and extend `..._sensitive_copy_sources` so that business-data pastes stand out.
- **No content inspection.** The rule knows that a paste happened and where it went, not what was pasted. Island did not record a payload hash on AI pastes in validation. Use Island's own DLP or AI data-protection policies for content classification. A paste that Island blocked still scores, at half weight.
- **Device attribution.** With the Island browser extension, the device hostname was empty for every AI paste in validation, so only the user receives risk. `src_display` then reads "an unidentified device".
- **Late events.** About 1 in 20 pastes reached Splunk more than 11 minutes late (the maximum seen was about 2.8 h). Pastes later than the 20-minute shift fall outside the window.
- **Hour boundaries.** Pasting split across two scheduled hours is counted separately in each.
- **Why the old copy→upload correlation was removed.** The previous logic paired any DLP "copy/paste/cut" event with any AI web traffic from the same user in the window, without time ordering. It also matched copy-to-USB and copy-to-share events. Clipboard copies are constant: the validation browser source logged about 4,300 Copy/Cut events per 30 minutes, so "a copy, then some AI traffic" is true for nearly every AI user. A recorded paste with its destination is direct evidence instead.
- **Other sources checked and not usable** in the validation tenants:
  - Microsoft Purview Endpoint DLP audit events: none in any tenant.
  - Sysmon Event ID 24 (ClipboardChange): not collected.
  - SSE/CASB logs: these record GenAI app "Browse" activity but no paste activity.
  - Proxy and NGFW logs: these cannot see clipboard content.

### Validation
Read-only live tests on 2026-10-09 across 4 production ES tenants:

| Tenant | Paste telemetry present? | Parses (search + 3 drilldowns) | Rows: own hourly window / 24 h (daily aggregate) | Notes |
|---|---|---|---|---|
| A | Yes. Island audit logs (browser extension); about 1,700 Paste events per 30 min overall, about 150–180 into AI pages per day from about 50 users | OK | 3, 1 and 0 (three runs at different hours) / 13 and 18 (two 24 h runs) | Providers: mostly OpenAI, also Google Gemini, Perplexity and Anthropic. After the same-site fix, a 24 h run kept 8 Gemini pastes copied from other Google services that the earlier registrable-domain comparison had dropped (1 user, 1 new finding); a 7-day review found at least 77 such pastes from about 20 users (Gmail, Docs, Chat, Apps Script into Gemini). Copy sources included webmail, online documents, ServiceNow and course sites, plus many pastes from outside the browser. 24 h scores were 20–40. No device hostname on AI pastes. The paste drilldown filters on `user` in the base search; with the user wildcarded it took about 220 s. |
| B | No (no Island, no DLP, no endpoint clipboard telemetry) | OK | 0 / 0 | Runs in about 10 s. |
| C | No (SSE logs GenAI browsing only; no DLP) | OK | 0 / 0 | Runs in about 5 s. |
| D | No | OK | 0 / 0 | Runs in about 2 s. |

The CIM `DLP` model was empty in all 4 tenants over 30 days. A synthetic test (rows piped through the full post-collection logic) confirmed each case:
- 3 pastes into ChatGPT copied from a SharePoint page fired at base 30.
- Same-site resolution: Gemini pasted from `mail.google.com`, `docs.google.com` or `google.com`, NotebookLM from `drive.google.com`, and ChatGPT from `outlook.cloud.microsoft` were all kept (Docs, Drive and Outlook classed `business_app`). Gemini from `gemini.google.com`, ChatGPT from `chat.openai.com` or `sora.chatgpt.com`, and Claude from `console.anthropic.com` were dropped as same-provider.
- Blocked verdicts: `allowed`+`blocked` on one row counted as not blocked; `blocked` alone and `Block`+`Deny` counted as blocked.
- 2 pastes did not fire.
- Same-site copies and Address Bar pastes were dropped.
- A DLP paste row with user `unknown` and a hostname fired on the device only, at half score because it was blocked.
- A row with an IP-only `src` and no user was dropped.
- A DLP row whose destination was an internal host was dropped.

No run returned a FATAL or ERROR message. The previous version failed in every tenant with `Data model 'Data_Loss_Prevention' was not found`. Its web-activity drilldown ran 259 s in Tenant A and hit the 300 s limit in Tenant B.

### Deployment
The package ships with `enable_alerting: false` and `deployment_type: adhoc`. Before enabling it for a tenant:
- Confirm one of the `data_prereqs` searches returns data.
- Set the Island index in `..._paste_events`.
- Derive `..._min_pastes` from the 7-day profile.
- Add the tenant's business application domains to `..._sensitive_copy_sources`.
- Allowlist sanctioned AI tools in `ai_sanctioned_entities`.

The rule is risk-only. Enabling it must be one separately approved change.
