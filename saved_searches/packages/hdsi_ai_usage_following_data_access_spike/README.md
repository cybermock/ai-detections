## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds a user who **touches an unusually large number of distinct files and, in the same hour, uploads data to an AI service** such as ChatGPT, Gemini, Claude, Perplexity, DeepSeek or an AI API. Gathering files from a share or a local disk and then pasting or attaching them into an AI assistant is a common way for sensitive data to leave the organisation, intentionally or not. The file side comes from file-share or endpoint file auditing (`Endpoint.Filesystem`). The upload side comes from firewall App-ID sessions (`Network_Traffic`) or proxy/SSE logs with byte counts (`Web`). The rule creates risk on the `user` only. The uploading address is reported as context (`src`, `upload_srcs`). It creates no notable. It feeds the collection phase of `hdsi_rba_ai_data_collection_kill_chain`.

v1.0 joined the two sides on `user` **and** `src`. File auditing records the file server or endpoint as `dest`, as a hostname, while network logs record the client IP as `src`, so the join could never match. It also counted only `read`/`created`/`modified`/`accessed`/`opened` actions, which real feeds do not use for file reads, and it read only the `Web` data model, which had no byte counts for AI traffic on any validation tenant. It returned 0 rows everywhere. v1.1 joins on a normalised user name, uses an action deny list, counts only document and data files (operating-system, software and servicing paths and binary extensions are excluded), adds the firewall App-ID path, drops Splunk's own audit trail and shared accounts, and runs hourly.

### Prerequisites
| Data | Fields used | Needed for | If absent |
|---|---|---|---|
| `Endpoint.Filesystem` (accelerated) with **per-file** access auditing: Windows file-share auditing (5145) or object access (4663) on file servers, EDR file events, or Microsoft 365 SharePoint/OneDrive file events where your add-on maps them | `user`, `file_path`, `file_name`, `action`, `dest`, `sourcetype` | The data access spike. Required | The rule returns nothing. Share-level events (5140) and records without a file name (`file_name` has no dot) are ignored, because they say nothing about how many files were read. Most Windows object-access volume is servicing, patching and software deployment under `Windows`, `Program Files`, `ProgramData`, `AppData` and admin shares; those paths and binary extensions are excluded (see Tuning macros), so the auditing must cover the shares or folders where users keep data |
| `Network_Traffic` (accelerated) from an NGFW with application identification (PAN-OS App-ID or similar) and **User-ID** | `app`, `user`, `src`, `bytes_out`, `action` | AI upload volume per user | Needs `Web` instead. Sessions without a user cannot be correlated |
| `Web` (accelerated) from a proxy or SSE/CASB that logs user and request bytes | `url_domain` or `site`, `user`, `src`, `bytes_out`, `action` | AI upload volume per user | Needs `Network_Traffic` instead. PAN-OS URL logs carry no byte counts and add nothing |

At least one of the two upload sources is required. Both are joined with `append`, and a missing data model only empties its own branch. `package.yml` expresses this as a required `Endpoint.Filesystem` data model plus two prerequisite searches: per-file events with a user (excluding `audittrail`), and user-attributed `bytes_out` in `Network_Traffic` **or** `Web`. The second check is coarse (any user-attributed traffic, not AI traffic specifically), so still run the upload Threshold SPL before enabling.

- **User names must line up.** The join key is the user lowercased, with any `DOMAIN\` prefix and any `@suffix` removed (`CORP\JSmith`, `jsmith@corp.example` and `jsmith` all become `jsmith`). This works when the UPN prefix equals the sAMAccountName. If your UPNs differ (for example `john.smith@` against `jsmith`), the rule cannot correlate those users.
- `ai_domains_filter` (common) resolves the App-ID, hostname or SSE app name to `provider`, `usage_type` and `severity_weight` through `ai_provider_apps` and `ai_provider_domains`. Only enabled rows count.
- `ai_unsanctioned_filter(3)` removes approved user, host, identity group or organisation-wide (`*|<provider>`) entries listed in `ai_sanctioned_entities`. It is called with the **normalised user key**, so a user entry must be the bare lowercase name (`jsmith|openai`), not `CORP\jsmith` or `jsmith@corp.example`. The group is the ES identity `bunit`, which the macro looks up itself from the same key.
- `ai_risk_multiplier` uses the ES `identity_lookup_expanded` `bunit` (through `ai_department_sensitivity`) and privileged status. Unknown users get 1.0.
- Requires the prerequisite package `hdsi_ai_rba_common`. The `data_access_spike_count` row in `ai_detection_config` is no longer read. The thresholds are macros in this package.

### How it works
- **File branch:** `tstats` over `Endpoint.Filesystem` collects distinct `file_path` values per `user`. Only records whose `file_name` contains a dot are counted. Actions in `..._excluded_actions` (deleted, failure, blocked, denied, acl_modified), sourcetypes in `..._excluded_sourcetypes` (Splunk `audittrail`), paths in `..._excluded_paths` (`\Windows\`, `WinSxS`, `System32`, `Program Files`, `ProgramData`, `AppData`, `Users\Default`, `ADMIN$`, `IPC$`, `SYSVOL`, `NETLOGON`, recovery and replication folders) and file names in `..._excluded_extensions` (`.dll`, `.exe`, `.sys`, `.mui`, `.cat`, `.cdf-ms`, `.msi`, `.cab`, `.tmp`, `.temp`, `.ini`, `.lnk` and similar) are dropped inside the `where` clause, and `..._filter` is applied inline.
- **User normalisation:** users are reduced to the join key (see Prerequisites). Machine accounts (`*$`), `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `ANONYMOUS LOGON` and placeholders (`unknown`, `-`) are dropped. A user with at least `..._min_files` (100) distinct files in the window is a spike. The count is the number of distinct paths across all raw user forms and hosts, so `CORP\jsmith` and `jsmith@corp.example` touching the same file count it once.
- **Upload branches (`append`):** the firewall App-ID branch (pre-filtered by `..._app_ids`, sessions with a user only) and the `Web` branch (`url_domain`, or the SSE app name in `site`) sum `bytes_out` per user for sessions that were not blocked. Both resolve the provider with `ai_domains_filter`, keep only `..._usage_types` (web, api, cli, model_registry), drop `..._excluded_providers` (Microsoft 365 Copilot) and approved entities. Sessions without a source address are kept (they count toward the volume, and `upload_srcs` then reads `none logged`). Each branch returns only users at or above `..._min_upload_mb` (5 MB), so the subsearch row limit is never reached. When the firewall and the proxy both see the same uploads, the larger total is used, not the sum.
- **Correlation:** a user must appear in the file branch and in an upload branch, and the first file access must come before the last upload. Users who uploaded from more than `..._max_upload_srcs` (5) source addresses in the hour are dropped as shared or generic accounts.
- **Scoring:** base 40, plus 10 when the file count is at least 5 × `..._min_files`, plus 10 when the upload is at least 10 × `..._min_upload_mb`. `risk_score = min(70, round(base × risk_multiplier × severity_weight))`, where `severity_weight` is the highest provider weight (0.3 to 1.2). The `_risk` literal fallback is 40.
- **Risk object:** the `user` only. The uploading host is not scored: the computed `risk_score` would apply to every risk object in the row, so a shared NAT, VDI or VPN address would collect the full user score from every user behind it, and `hdsi_rba_ai_data_collection_kill_chain` uses `system` events only when a row has no user, which never happens here. `src` (the address that sent the most bytes to AI services in the hour) and `upload_srcs` (up to 5 addresses, or `none logged`) stay in the event as context. No risk object is ever `unknown`.
- **Cadence:** hourly at minute 13 over `-65m@m` to `-5m@m`. Suppression is 4 hours per `user`.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_usage_following_data_access_spike_filter` | `()` | Exclusions inside the `Endpoint.Filesystem` where clause (`Filesystem.*` names), e.g. backup, indexing, antivirus or migration accounts |
| `hdsi_ai_usage_following_data_access_spike_excluded_actions` | `"deleted","failure","failed","blocked","denied","acl_modified"` | `Filesystem.action` values that are not data access |
| `hdsi_ai_usage_following_data_access_spike_excluded_sourcetypes` | `"audittrail"` | `Endpoint.Filesystem` sourcetypes that are not user file access |
| `hdsi_ai_usage_following_data_access_spike_excluded_paths` | `"*\\Windows\\*","*\\Program Files\\*","*\\ProgramData\\*","*\\AppData\\*","*\\ADMIN$\\*","*\\SYSVOL\\*", ...` (17 patterns) | `file_path` patterns that are OS, software, profile, recovery or replication locations, not user data. Remove a pattern only if users keep data there |
| `hdsi_ai_usage_following_data_access_spike_excluded_extensions` | `"*.dll","*.exe","*.sys","*.mui","*.cat","*.cdf-ms","*.msi","*.cab","*.tmp","*.temp","*.ini","*.lnk", ...` (29 patterns) | Binary, installer, servicing, temporary and shell-metadata file names |
| `hdsi_ai_usage_following_data_access_spike_min_files` | `100` | Distinct files per user per hour that count as a spike |
| `hdsi_ai_usage_following_data_access_spike_min_upload_mb` | `5` | MB the same user must upload to AI services in the hour |
| `hdsi_ai_usage_following_data_access_spike_max_upload_srcs` | `5` | More uploading addresses than this means a shared account, and the row is dropped |
| `hdsi_ai_usage_following_data_access_spike_app_ids` | `All_Traffic.app IN ("openai*","chatgpt*","claude*","anthropic*","google-gemini*", ...)` | Pre-filter of candidate App-IDs. It only narrows the search. A value counts only when `ai_provider_apps` has an enabled row for it (the common lookup now has `claude-base`, `claude-upload`, `claude-post`, `anthropic-api-base`, `anthropic-api-post`, `openai-base`, `openai-chatgpt-uploading`, `google-gemini-uploading`, `google-gemini-models`, `xai-grok` and more) |
| `hdsi_ai_usage_following_data_access_spike_network_filter` | `()` | Exclusions inside the `Network_Traffic` where clause (`All_Traffic.*` names) |
| `hdsi_ai_usage_following_data_access_spike_web_filter` | `()` | Exclusions inside the `Web` where clause (`Web.*` names). Add inbound server sourcetypes (load balancer, WAF, IIS) here to make the branch faster |
| `hdsi_ai_usage_following_data_access_spike_usage_types` | `"web","api","cli","model_registry"` | Which `usage_type` values count. Add `"ide"` to include coding assistants |
| `hdsi_ai_usage_following_data_access_spike_excluded_providers` | `"Microsoft 365 Copilot"` | Providers whose uploads are not counted. Use `"__none__"` to count all |
| `hdsi_ai_usage_following_data_access_spike_customizations` | `search *` | Post-scoring hook (fields: `user`, `src`, `upload_srcs`, `upload_src_count`, `provider`, `evidence`, `ai_mb`, `file_count`, `file_events`, `file_hosts`, `file_sample`, `first_file_time`, `last_file_time`, `last_upload_time`, `base_score`, `severity_weight`, `risk_multiplier`, `risk_score`) |
| `hdsi_ai_usage_following_data_access_spike_risk_score` | `search *` | Last pipe. Override `risk_score` (1 to 100) here |

Per-user, per-host, per-group or organisation-wide approvals (for example a data-science team allowed to send files to an AI API, or an Anthropic API integration server) go in `ai_sanctioned_entities` (common package), keyed `<user, src, bunit or *>|<provider>` and matched case-insensitively. Write users as the normalised key: without `DOMAIN\` and without `@suffix` (`jsmith`, not `CORP\jsmith` or `jsmith@corp.example`). Entries in any other user form never match. Host entries match any upload address of the user, so an approved integration server is removed before the volume is summed.

### Threshold
Both thresholds are per user per hour, the window the rule runs on. Measure them over at least a day with the same exclusions as the rule. Each SPL uses the package macros, so tuned exclusions are included. The figures below are dated snapshots (2026-10-09); your own distribution, and the next day's, will differ.

**`..._min_files`** should sit well above the data files a normal user touches in an hour, so that only real collection counts. Set it near the 99th percentile of this search (never below about 25):

```spl
| tstats summariesonly=t allow_old_summaries=t values(Filesystem.file_path) as file_path
    from datamodel=Endpoint.Filesystem
    where Filesystem.file_name="*.*"
      NOT Filesystem.action IN (`hdsi_ai_usage_following_data_access_spike_excluded_actions`)
      NOT sourcetype IN (`hdsi_ai_usage_following_data_access_spike_excluded_sourcetypes`)
      NOT Filesystem.file_path IN (`hdsi_ai_usage_following_data_access_spike_excluded_paths`)
      NOT Filesystem.file_name IN (`hdsi_ai_usage_following_data_access_spike_excluded_extensions`)
      `hdsi_ai_usage_following_data_access_spike_filter`
    by _time span=1h Filesystem.user
| rename Filesystem.* as *
| eval ukey=lower(replace(replace(trim(user),"^.*\x5c",""),"@.*",""))
| where NOT match(ukey,"\$$") AND NOT ukey IN ("unknown","-","n/a","null","none","system","local service","network service","anonymous logon")
| stats dc(file_path) as files by _time ukey
| stats count as user_hours dc(ukey) as users perc95(files) as p95 perc99(files) as p99 max(files) as max
    count(eval(files>=25)) as ge25 count(eval(files>=50)) as ge50 count(eval(files>=100)) as ge100 count(eval(files>=250)) as ge250
```

On the tenant with per-file auditing (Tenant A), 24 hours: 372 user-hours with data files (155 users), 95th percentile 22 files, 99th about 140, maximum 249. 15 user-hours reached 25 files and 9 reached 100. Before the path and extension exclusions the same day had 514 user-hours, a 99th percentile of about 690 and 41 user-hours at 100 or more: about 90 % of the files in those spikes were Windows servicing (`$WinREAgent`, `WinSxS`), default-profile and `AppData` files, `Program Files` and `ProgramData`, so the old count mostly measured patching and software installs. The shipped 100 sits near the 99th percentile. On the tenant whose only per-file data is Microsoft 365 SharePoint (Tenant D) the maximum was 11 files per user-hour (99th percentile 7). Lower `..._min_files` to about 25 there if you want the SharePoint path to be able to fire.

**`..._min_upload_mb`** is checked separately for each upload source, so measure each source on its own. The distribution covers **every** user-hour with an AI session, not only the heavy ones. It depends on which App-IDs and domains are enabled in `ai_provider_apps` / `ai_provider_domains`, so re-run it whenever the common lookups change. Firewall App-ID source:

```spl
| tstats summariesonly=t allow_old_summaries=t sum(All_Traffic.bytes_out) as bytes_out
    from datamodel=Network_Traffic
    where All_Traffic.user=* All_Traffic.bytes_out>0 NOT All_Traffic.action="blocked"
      `hdsi_ai_usage_following_data_access_spike_app_ids`
      `hdsi_ai_usage_following_data_access_spike_network_filter`
    by _time span=1h All_Traffic.user All_Traffic.app
| rename All_Traffic.* as *
| eval ai_domain=app, ai_input_type="app"
| `ai_domains_filter`
| search usage_type IN (`hdsi_ai_usage_following_data_access_spike_usage_types`)
    NOT provider IN (`hdsi_ai_usage_following_data_access_spike_excluded_providers`)
| eval ukey=lower(replace(replace(trim(user),"^.*\x5c",""),"@.*",""))
| where NOT match(ukey,"\$$") AND NOT ukey IN ("unknown","-","n/a","null","none","system","local service","network service","anonymous logon")
| stats sum(bytes_out) as bytes_out by _time ukey
| eval mb=bytes_out/1048576
| stats count as user_hours dc(ukey) as users median(mb) as p50 perc95(mb) as p95 perc99(mb) as p99 perc99.9(mb) as p99_9 max(mb) as max
    count(eval(mb>=1)) as ge1 count(eval(mb>=5)) as ge5 count(eval(mb>=10)) as ge10 count(eval(mb>=50)) as ge50
```

For the proxy/SSE source, replace everything before `` | `ai_domains_filter` `` with:

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" sum(Web.bytes_out) as bytes_out
    from datamodel=Web
    where (Web.url_domain=* OR Web.site=*) Web.bytes_out>0 NOT Web.action="blocked" NOT Web.user="unknown"
      `hdsi_ai_usage_following_data_access_spike_web_filter`
    by _time span=1h Web.user Web.url_domain Web.site
| rename Web.* as *
| eval ai_domain=lower(coalesce(nullif(url_domain,"unknown"),nullif(site,"unknown"))),
    ai_input_type=if(isnull(nullif(url_domain,"unknown")),"app","host")
```

On Tenant A (firewall App-ID with User-ID), 6 hours, with the current common lookup (which now resolves the Claude, Anthropic API, OpenAI base/upload, Gemini upload/models and xAI Grok App-IDs): 113,152 user-hours with AI sessions (about 34,800 users). The median was 0.007 MB, the 95th percentile 0.16 MB, the 99th 0.60 MB and the 99.9th 2.8 MB, with a maximum of 166 MB. 487 user-hours reached 1 MB, 71 (0.06 %) reached 5 MB, 41 reached 10 MB and 14 reached 50 MB. Before those App-IDs resolved, the 24-hour 99.9th percentile was 1.9 MB and 137 user-hours reached 5 MB; a 24-hour measurement with them gave 2.5 MB and 296. The largest sources in 6 hours were `google-gemini` (about 4.3 GB), `anthropic-api-base` (about 1.7 GB, largely integration servers and agents), `openai-chatgpt`, `claude-base` and `claude-upload`. Ordinary chat use is well under 1 MB an hour, so the shipped 5 MB still sits above the 99.9th percentile; keep the value above your own. On Tenant C (SSE) only a handful of user-hours a day had user-attributed AI uploads, so the proxy source is sparse there. The firewall search over 6 hours took about 60 s on Tenant A; run it a few hours at a time.

### Known false positives / Limitations
- **Software deployment and patching (handled).** Without path and extension exclusions, Windows object auditing turns servicing, installs and profile creation into hundreds of "files" per hour, and an admin or deployment account using an AI service in the same hour would score as data collection. `..._excluded_paths` and `..._excluded_extensions` remove this. If your deployment tooling writes elsewhere (for example `D:\Apps\`), add that path.
- **Periodic background pairs.** In the first validation round, at a 1 MB upload threshold and without path exclusions, one shared account on Tenant A paired every hour: about 300 profile and cache files from a file-share process and about 1.5 MB to Google Gemini, from 31 addresses. The path exclusions, the 5 MB threshold and the `..._max_upload_srcs` guard each remove it. Treat any steady, every-hour pair the same way.
- **API integration servers and agents.** API App-IDs such as `anthropic-api-base` (about 1.7 GB in 6 hours on Tenant A) carry heavy, steady uploads from integration servers and coding agents. When such a host also runs a service account with file auditing, the pair is real but expected: approve the host or account in `ai_sanctioned_entities` (`<src>|anthropic`) or exclude it with `..._network_filter`.
- **Shared file servers inflate counts.** File-share auditing logs every file a client opens, including folder browsing and application caches on data shares. Exclude backup, scanning, indexing and migration accounts with `..._filter`.
- **Coarse sequence.** Both sides are measured in the same one-hour window, and the only order check is "first file access before last upload". Collection at 10:50 followed by an upload at 11:10 falls into two windows and is missed. The rule does not prove that the files were the data uploaded. It shows that both happened close together.
- **User-name formats.** The join depends on the normalised user name (see Prerequisites). Firewalls without User-ID, and proxies that log only an IP address, cannot be correlated. On Tenant A more than half of the AI App-ID upload volume had no user.
- **Wrong data in `Endpoint.Filesystem`.** Validation found Windows logon, lockout and share-level events tagged into `Endpoint.Filesystem` (Tenant A), Splunk's own `audittrail` (Tenants C and D) and Microsoft 365 SharePoint events with `action=unknown` (Tenant D). The `file_name` dot rule, the action deny list and the sourcetype exclusion handle what was seen. Check your own `sourcetype` and `action` mix in `Endpoint.Filesystem` before enabling.
- **Not counted by default:** Microsoft 365 Copilot (`..._excluded_providers`) and IDE assistants such as `openai-codex`, GitHub Copilot and Cursor (`usage_type` `ide`, see `..._usage_types`).
- **Drilldowns** match the raw user with a wildcard and then keep only rows whose normalised key equals `$user$` exactly, so `smith` does not pull in `jsmith`. They filter on the user only, because `src` can be empty.

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09. The "scheduled window" run used the hourly logic over the last 4 hours.

| Tenant | Per-file data in `Endpoint.Filesystem` | User-attributed AI upload data | Parses (search + 4 drilldowns) | v1.0 rows | v1.1 rows (scheduled window) | Pairs in 24 h at 25 files and 1 MB | Notes |
|---|---|---|---|---|---|---|---|
| A | Yes: Windows object/share auditing. After the path and extension exclusions, 372 user-hours with data files a day (9 at 100 or more). Also many mis-tagged logon/share-level events, which are ignored | Yes: firewall App-ID with User-ID (`DOMAIN\user` and UPN). Web is URL logs without bytes | OK | 0 | 0 (about 48 s) | 0 | With every threshold at its floor (1 file, 0.001 MB, guard off) the full pipeline returned one correctly built row (base 40, `risk_score` 40, user-only, `src` and `upload_srcs` filled), so the correlation path works; no real user combined a data-file spike with an AI upload in the day |
| B | No (no file events) | Only inbound load balancer/WAF and a small DNS-security proxy without users | OK | 0 | 0 (12 s) | not run | No data path |
| C | No: only Splunk `audittrail`, excluded | Yes: SSE with UPN users and bytes | OK | 0 | 0 (9 s) | not run | SharePoint file events exist in raw Microsoft 365 audit data but are not mapped to `Endpoint.Filesystem` |
| D | Microsoft 365 SharePoint file events only (at most 11 files per user-hour; the exclusions remove none) | None | OK | 0 | 0 (7 s) | 0 | No upload data path |

There were no FATAL or ERROR messages on any tenant. Earlier rounds (same day) also confirmed that `src` is the highest-volume upload address for every user in one hour of Tenant A firewall data (22,487 users), and that the `package.yml` prerequisite searches pass on Tenants A and D and fail the file check on B and C.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:

1. Confirm that `Endpoint.Filesystem` holds per-file access events with users on the shares or folders where users keep data (run the files Threshold SPL) and that at least one upload source carries users and `bytes_out` for AI traffic.
2. Check that user names line up between the two sides (`DOMAIN\user`, UPN prefix and bare name must reduce to the same key).
3. Review `..._excluded_paths` and `..._excluded_extensions` against your own deployment tooling, then derive `..._min_files` and `..._min_upload_mb` from the Threshold SPLs. Add backup, scanning and migration accounts to `..._filter`, VDI or NAT ranges to `..._network_filter` or `..._web_filter`, and approved users, hosts, groups or integration servers to `ai_sanctioned_entities`.
4. Run the search over the scheduled window and in hourly buckets over a day, and confirm the expected risk volume.

The rule is risk-only (no notable). Enabling it is a separately approved change.
