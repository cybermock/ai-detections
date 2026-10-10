## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds hosts, and users where the firewall knows them, that are running an **AI coding assistant**: GitHub Copilot, Cursor, Windsurf (Codeium), JetBrains AI Assistant, Amazon Q Developer and Kiro, Gemini Code Assist, Tabnine, Sourcegraph Cody, OpenAI Codex, Supermaven and Augment Code. These tools send open source files and repository context to a third-party model. The rule treats the organisation's own GitHub Copilot Business/Enterprise seats as sanctioned. It scores **personal-tier Copilot** higher, because that means code going to a personal GitHub account outside the organisation's data-retention and training controls. It creates risk on `src` (system) and, when exactly one firewall user is seen for that source, on `user`. It creates no notable.

v1.0 looked for IDE process names (`code.exe`, `cursor.exe`...) in `Network_Traffic.app` and matched AI hostnames in `dest`. Firewalls put an application ID or protocol in `app` and an IP address in `dest`, so v1.0 returned 0 rows on all four validation tenants. It also hard-coded `user="unknown"`. v1.1 uses the two places where code-assistant traffic is actually identified: firewall App-ID values and DNS names that only the assistants resolve.

### Prerequisites
Either data path is enough. The branches are joined with `append`, and a missing data model only empties its own branch (`data_prereqs` op `OR`).

| Data | Fields used | What it adds | If absent |
|---|---|---|---|
| `Network_Traffic` (accelerated) from an NGFW with application identification (PAN-OS App-ID or equivalent) | `app`, `src`, `user`, `action` | Tool identity from the firewall (`github-copilot`, `github-copilot-business`, `cursor`, `codeium`, `openai-codex`, `amazon-codewhisperer`), the user from firewall User-ID, and whether the session was blocked | No user attribution. OpenAI Codex is not visible, because it has no dedicated DNS name. Firewalls that put only protocol or port in `app` (ASA, FortiGate without application control) contribute nothing |
| `Network_Resolution` (accelerated) from client-facing DNS logs (resolver, DNS security service, network capture) | `query`, `src` | Tool identity from vendor API hostnames, including the GitHub Copilot license tier (`*.individual`, `*.business`, `*.enterprise.githubcopilot.com`) | No tier information except the App-ID `github-copilot-business` value |

- `src` must be the **client**. DNS logs that show an internal forwarder as the client report the forwarder. Exclude it with `..._dns_filter`.
- Uses `ai_unsanctioned_filter(3)` (approvals in `ai_sanctioned_entities`) and `ai_risk_multiplier` (ES `identity_lookup_expanded` `bunit` sensitivity) from `hdsi_ai_rba_common`, which makes `hdsi_ai_rba_common` a required prerequisite package. See "Approvals" below for which keys apply to which rows.
- The common registries (`ai_provider_domains`, `ai_provider_apps`) do list code-assistant hosts and App-IDs (`githubcopilot.com`, `cursor.sh`, `codeium.com`, `kiro.dev`, `grazie.aws.intellij.net`, `cloudcode-pa.googleapis.com`, `github-copilot*`...), and this package uses **the same provider strings** for them. It does not call `ai_domains_filter`, for three reasons: the `tstats` pre-filter needs literal names; the registry deliberately also covers vendor sites and downloads (`cursor.com`, `tabnine.com`, `windsurf.com` with all subdomains), which are not evidence that the tool runs; and the registry has no Copilot license tier. The narrower endpoint list lives in `..._dns_endpoints`, and `..._tool_map` turns each endpoint into a tool, a provider and a license tier.

### How it works
- **App-ID branch:** `tstats` over `Network_Traffic`, pre-filtered inline by `..._app_ids` and `..._filter`, split by `src`, `user`, `app`. Matching is case-insensitive.
- **DNS branch (`append`):** `tstats` over `Network_Resolution`, pre-filtered inline by `..._dns_endpoints` and `..._dns_filter`, split by `src`, `query`. Every name is listed with and without the trailing root dot, because some DNS security services log `api2.cursor.sh.`. The bare `api.jetbrains.ai` is deliberately not listed: every JetBrains IDE with the bundled AI plugin resolves it while idle. JetBrains AI counts only when `*.grazie.aws.intellij.net` or `*.api.jetbrains.ai` (the model traffic) is seen.
- **Tool mapping:** `..._tool_map` normalises the endpoint (lower-case, trailing dot stripped) and sets `tool`, `provider` and `license_tier` (`personal`, `organisation` or `unknown`). Rows it cannot map are dropped. `provider` is the registry string for the same host or App-ID: `GitHub Copilot` (all tiers), `Cursor`, `Windsurf`, `Tabnine`, `Sourcegraph`, `Amazon Q`, `Kiro`, `JetBrains AI`, `Google Gemini` (Gemini Code Assist), `OpenAI` (Codex). `Supermaven` and `Augment Code` are not in the registry and use the tool name. One `ai_sanctioned_entities` key therefore covers this rule and the suite's DNS, Web and firewall rules for that provider.
- **Copilot tier:** when a source resolves org-tier Copilot hostnames at any time in the day, its generic Copilot endpoints (`api.githubcopilot.com`, `copilot-telemetry.githubusercontent.com`) are treated as org-tier too. This is why the rule runs over a whole day (see Cadence). The org-tier App-IDs are `github-copilot-business` and `github-copilot-chat-business`.
- **Idle Copilot installs:** a source whose only unknown-tier Copilot evidence is DNS for the background hosts `copilot-telemetry.githubusercontent.com`, `telemetry.githubcopilot.com` or `exp-tas.githubcopilot.com` (telemetry and experiment assignment, sent by an installed extension without any prompt) loses those rows. This is the same rule as for idle JetBrains IDEs. A Copilot App-ID session, or a DNS lookup of `api.githubcopilot.com` or `copilot-proxy.githubusercontent.com`, from the same source keeps the source.
- **User for the whole host:** when the firewall saw exactly one user for a source that day, that user is copied to the source's DNS rows before the approval check. This is the same attribution the per-host aggregation already made, applied early enough that a per-user approval also removes that host's DNS rows.
- **Sanctioned tools:** `..._sanctioned_tools` (ships as org-tier Copilot) is removed, then `ai_unsanctioned_filter(user,src,provider)` applies the `ai_sanctioned_entities` approvals (see "Approvals").
- **Risk objects:** placeholder users (`unknown`, `-`, empty) are nulled. Results are aggregated to **one row per `src`**. `user` is set only when exactly one firewall user was seen. A source with more users than `..._max_users_per_src` is treated as shared egress (proxy, NAT, VDI) and dropped. Rows whose `src` matches `..._unreliable_src` and have no user are dropped (opt-in; ships off). No row carries an `unknown` risk object.
- **Scoring:** base 25 when personal-tier Copilot completions or chat traffic is seen (`api.` or `proxy.individual.githubcopilot.com`). Base 5 when every firewall session was blocked. Base 15 otherwise. `risk_score = min(50, round(base x risk_multiplier))` applies to both `src` and `user`. The `_risk` literal fallbacks are 15 and 15.
- **Cadence:** daily at 01:20 over the previous calendar day (`-1d@d` to `@d`), suppressed 20 h per `src` to absorb manual re-runs. Running a coding assistant is a daily habit, not an event, so one row per host per day is the right unit. An hourly run with 24 h suppression was tested and rejected: the 1 h window misses org-tier context (on Tenant B, 52 of about 1,375 org-tier Copilot hosts would have been flagged as unknown-tier Copilot each day), and suppression locked in the score of the first matching hour (6 of 37 active personal-tier Copilot hosts on Tenant B would have been scored 15 or 5 instead of 25). The daily window scores each host on its full day of evidence. The trade-off is latency of up to about 25 h, which is acceptable for an informational usage signal.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_code_assistant_network_connection_filter` | `()` | Exclusions inside the `Network_Traffic` where clause (`All_Traffic.*` names), e.g. a developer VDI subnet that is approved |
| `hdsi_ai_code_assistant_network_connection_dns_filter` | `()` | Exclusions inside the `Network_Resolution` where clause (`DNS.*` names). Add internal resolvers or forwarders that appear as the DNS client |
| `hdsi_ai_code_assistant_network_connection_app_ids` | `*github*copilot*`, `cursor`, `cursor-*`, `cursor.ai*`, `codeium*`, `*windsurf*`, `*tabnine*`, `openai-codex*`, `*codewhisperer*`, `amazon-q-developer*`, `sourcegraph-cody*`, `jetbrains-ai*`, `*gemini-code-assist*`, `*supermaven*` | Firewall App-ID values that name a coding assistant. Add your NGFW's names for the same tools. M365 Copilot and chat apps are deliberately absent |
| `hdsi_ai_code_assistant_network_connection_dns_endpoints` | Copilot, Cursor, Codeium/Windsurf, Tabnine, Cody, Amazon Q/CodeWhisperer, Kiro, JetBrains AI (`*.grazie.aws.intellij.net`, `*.api.jetbrains.ai`), Gemini Code Assist, Supermaven and Augment API hostnames | Names the tools resolve. Marketing and download sites (including the Kiro installer host `*download*.kiro.dev`, excluded with a `NOT` clause in the same macro) and the idle-IDE name `api.jetbrains.ai` are left out. Every new entry needs a `..._tool_map` pattern |
| `hdsi_ai_code_assistant_network_connection_tool_map` | `eval` mapping | Endpoint to `tool`, `provider`, `license_tier` |
| `hdsi_ai_code_assistant_network_connection_sanctioned_tools` | `"GitHub Copilot (Business/Enterprise)"` | Tool labels licensed for everyone, removed in this rule only. Add e.g. `"GitHub Copilot"` when the firewall cannot see the tier and Copilot is licensed company-wide; `"GitHub Copilot (personal)"` stays reported. Use `"__none__"` to report every tool |
| `hdsi_ai_code_assistant_network_connection_max_users_per_src` | `3` | Shared-egress guard (see Threshold) |
| `hdsi_ai_code_assistant_network_connection_unreliable_src` | `false()` | Eval expression for source addresses that are not a stable host. Matching rows without a firewall user are dropped. For roaming DNS security clients use e.g. `cidrmatch("192.168.0.0/16",src) OR match(src,":")`. Do not use it where those ranges are corporate LANs |
| `hdsi_ai_code_assistant_network_connection_customizations` | `search *` | Post-aggregation hook (fields: `src`, `user`, `users`, `user_display`, `tools`, `tool_list`, `provider`, `license_tiers`, `copilot_personal_active`, `evidence_type`, `endpoint_sample`, `event_count`, `action`, `allowed`, `base_score`, `risk_multiplier`, `risk_score`) |
| `hdsi_ai_code_assistant_network_connection_risk_score` | `search *` | Last pipe. Override `risk_score` (≤100) here |

#### Approvals
Approvals go in `ai_sanctioned_entities` (common package). The provider part of the key is the lower-cased `provider` string listed under "How it works" (`github copilot`, `cursor`, `windsurf`, `amazon q`, `jetbrains ai`...). The check runs on each evidence row before the per-host aggregation:

| Key | Example `allow_key` | Removes |
|---|---|---|
| Host | `dev-ws-01\|cursor` | Every row of that `src` for that provider |
| User | `jdoe@example.com\|cursor` | That user's firewall rows, and the DNS rows of a host where the firewall saw only that user that day. A host with no firewall user, or with several, keeps its DNS rows: approve the host instead |
| Group | `engineering\|cursor` | Rows whose user (as above) has that ES identity `bunit` (the common macro looks it up, also by bare name for `DOMAIN\user` values). Never DNS rows of a host without a single firewall user |
| Organisation | `*\|cursor` | Every row for that provider |

Example row: `system,dev-ws-01,Cursor,provider,2099-12-31,security,approved_cursor_pilot,1,dev-ws-01|cursor`.

Two cautions. The provider strings are shared with the rest of the suite, so `*|github copilot` also quiets GitHub Copilot in the DNS and firewall detections, and `*|google gemini` or `*|openai` approve the Gemini and ChatGPT chat products everywhere, not only Gemini Code Assist and Codex. And an organisation key removes every Copilot tier, including personal-tier Copilot. To accept company-licensed Copilot but keep personal accounts visible, add `"GitHub Copilot"` to `..._sanctioned_tools` instead of using the `*|github copilot` key. Process-based detections use different strings for some of these tools (`Microsoft Copilot`, `Codeium`, `Amazon`; see the common README), so approving a tool everywhere can take one key per string.

### Threshold
`hdsi_ai_code_assistant_network_connection_max_users_per_src` defaults to 3. It only matters on the App-ID branch, where the firewall supplies `user`. The guard is evaluated over the daily window. A real workstation shows one user a day, occasionally two after a DHCP reassignment. An explicit proxy, NAT pool, VDI host or terminal server shows many. Measure your tenant over one or more full days, then set the value just below the first source count that belongs to known shared infrastructure:

```spl
| tstats summariesonly=t allow_old_summaries=t dc(All_Traffic.user) as users from datamodel=Network_Traffic
    where `hdsi_ai_code_assistant_network_connection_app_ids` All_Traffic.user=* NOT All_Traffic.user="unknown"
    by All_Traffic.src _time span=1d
| stats max(users) as max_users_per_day by All_Traffic.src
| stats count as srcs by max_users_per_day
| sort max_users_per_day
```

In validation (one full day), the only App-ID tenant with User-ID had 116 sources with 1 user, 3 with 2 and 1 with 4. The default drops only that one source.

### Known false positives / Limitations
- **DNS `src` is not always a stable host.** Roaming DNS security clients log the device's local address. In the two DNS-heavy tenants, about half of the daily rows (100 of 203 on Tenant B and 33 of 63 on Tenant C in the earlier run of this revision) had a home-network `192.168.x.x` or IPv6 `src` with no user, which different laptops can share and which can become a false RBA hotspot. Best fix: map the DNS service's device identity to `src` in the TA. Otherwise set `..._unreliable_src` (for example `cidrmatch("192.168.0.0/16",src) OR match(src,":")`) to drop those rows. It ships off because on a tenant whose LAN uses those ranges it would drop real hosts (on Tenant A the same expression would have dropped 21 of 224 rows in that run).
- **No user from DNS.** DNS-only tenants raise system risk only. The user appears only where the firewall has User-ID (90 of 181 rows on the App-ID tenant in the final run).
- **Firewall user form.** `user` is the firewall User-ID value, lower-cased, unchanged. On the App-ID tenant, UPN-form users matched ES identities (41 of 43). `DOMAIN\user`-form users matched only 1 of 55 as written and 3 of 55 by bare name; the common macros now try the bare name, so those 3 get `risk_multiplier` and group approvals, and the rest keep 1.0. The risk object stays `DOMAIN\user`, so it may not correlate with the same person's risk from other sources. Normalise the user in the firewall TA or add that form to the identity lookup if this matters.
- **App-ID usually cannot tell the Copilot tier.** `github-copilot` covers personal and business seats unless the vendor publishes a separate business App-ID. Where Copilot is licensed company-wide, add `"GitHub Copilot"` to `..._sanctioned_tools`. Otherwise the tenant can expect about one 15-point risk event per Copilot host per day. In validation that was 116 to 132 hosts a day on the App-ID tenant.
- **Personal-tier sign-in without use.** VS Code signed in to a personal GitHub account resolves `exp.` and `telemetry.individual.githubcopilot.com` even when Copilot is idle. Those hosts are reported at 15, and only `api.`/`proxy.individual` traffic (actual completions or chat) scores 25. Hosts that resolve both org-tier and personal-tier names are reported on purpose. That is usually a personal account on a corporate machine, but roaming-address collisions can cause it too.
- **Idle Copilot installs are excluded.** On Tenant B, 18 sources a day (1 on Tenant C) resolved only Copilot telemetry or experiment hosts, a median of 2 queries a day, and are no longer reported. A host with Copilot installed but never used is therefore silent. Personal-tier sign-in (below) is still reported.
- **Idle JetBrains IDEs are excluded.** In Tenant B, 29 of 43 hosts that resolved `api.jetbrains.ai` resolved nothing else from JetBrains AI (median 2 queries a day), while hosts that also reached `*.grazie.aws.intellij.net` had a median of over 200. The bare name is therefore not in the list, which cut JetBrains rows on Tenant B from 41 to 11 a day. A host that signs in to JetBrains AI but never sends a prompt is not reported.
- **Claude Code, Codex CLI and Gemini CLI** use general-purpose API hostnames (`api.anthropic.com`, `chatgpt.com`, `cloudcode-pa.googleapis.com`). The first two cannot be told apart from other API or web use by DNS, so they are not covered here. The suite's CLI and API detections cover them. `cloudcode-pa.googleapis.com` is labelled Gemini Code Assist and also matches Gemini CLI.
- **Amazon Q means Amazon Q, not only the IDE.** `q.<region>.amazonaws.com` is used by the Amazon Q IDE plugins and also by the Amazon Q chat panel in the AWS console. On Tenant B, all 21 sources that resolved it also resolved the AWS console, and 6 of them showed no IDE indicator. The rows are labelled `Amazon Q Developer` either way; treat them as Amazon Q use.
- **Kiro installer downloads are excluded** (`prod.download.desktop.kiro.dev` was resolved by 2 hosts on Tenant B). Kiro's own telemetry host `*.telemetry.desktop.kiro.dev` is still counted, so an installed but unused Kiro can be reported (6 hosts a day on Tenant B).
- **Firewall-blocked sessions** still prove the tool is installed. They score 5 instead of 15.
- **Duplicate firewall feeds** (on-prem and cloud log forwarding of the same sessions) inflate `event_count` but not risk.
- **Vendor endpoints change.** Review `..._dns_endpoints` and `..._app_ids` when a tool changes its backend. A name with no `..._tool_map` pattern is silently dropped, never mis-labelled.

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09. The v1.1 runs used the exact scheduled window (`-1d@d` to `@d`, the previous calendar day), so the row count equals one day of risk events. The table shows the final run of this revision.

| Tenant | Data paths present | Parses (search + 3 drilldowns) | v1.0 rows | v1.1 rows (scheduled daily window) | Score mix | Notes |
|---|---|---|---|---|---|---|
| A | NGFW App-ID (Network_Traffic) plus partial DNS | OK | 0 | 181 (154 s) | 157 at 15, 20 at 5 (all sessions blocked), 4 at 25 (active personal Copilot); 1 row raised by `risk_multiplier` | Copilot (App-ID, tier unknown) 116 hosts, Cursor 45, OpenAI Codex 20, Gemini Code Assist 7, personal Copilot 4, Windsurf 3. 90 rows carry a firewall user. The idle-Copilot rule removed 0 rows. An earlier run of the same window returned 224 rows with every tool higher in proportion, so the difference is in the firewall data, not the logic |
| B | DNS only (roaming DNS security service, trailing-dot names); `Network_Traffic` has no App-ID | OK | 0 | 181 (6 s) | 133 at 15, 48 at 25 | About 1,400 org-tier Copilot hosts removed by default; 18 idle Copilot installs (telemetry or experiment lookups only) removed. Personal Copilot 105 hosts (48 active), Cursor 28, Amazon Q 26, Copilot of unknown tier 23, JetBrains AI 14, Gemini Code Assist 9, Kiro 6, Tabnine 2. No user attribution. About half the rows are on roaming addresses |
| C | DNS (roaming DNS security service) plus small App-ID | OK | 0 | 56 (7 s) | 31 at 15, 25 at 25 | About 600 org-tier Copilot hosts removed by default; 1 idle Copilot install removed. Personal Copilot 41 hosts (25 active), Copilot of unknown tier 11, Amazon Q 6, JetBrains AI 4, Gemini Code Assist 3, Cursor 2. App-ID shows `github-copilot` and `github-copilot-business` with no User-ID. About half the rows are on roaming addresses |
| D | Neither: DNS server logs with no code-assistant names, and `Network_Traffic` without App-ID | OK | 0 | 0 | none | No data path. Expected silence |

No FATAL or ERROR messages on any tenant. A unit check of `..._tool_map` on every tenant labelled `github-copilot-chat-business` and `telemetry.business.githubcopilot.com` as org tier, `api.individual.githubcopilot.com` as personal, and gave each tool the registry provider string. The firewall drilldown filters `src` inside `tstats` and returns in about 10 s for one host over a day on the largest tenant. The DNS drilldown returns in under 45 s.

Expected daily volume, at most one event per host per day at 5 to 25 points (up to 50 with the multiplier): Tenant A about 180 (116 of them include unknown-tier Copilot; adding `"GitHub Copilot"` to `..._sanctioned_tools` removes the ones with no other tool), B about 180, C about 55 (about half of each with `..._unreliable_src` set), D none.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:

1. Confirm that at least one data path exists. Either `Network_Traffic.app` carries application IDs (run the `..._app_ids` filter alone), or `Network_Resolution` holds client DNS queries for the endpoint list.
2. Set `..._sanctioned_tools` to the tools the organisation licenses for everyone, and load per-user or per-host approvals into `ai_sanctioned_entities`.
3. Add internal DNS forwarders to `..._dns_filter`, derive `..._max_users_per_src`, and on roaming-DNS tenants decide whether to set `..._unreliable_src`.
4. Run the search once over the scheduled window (`-1d@d` to `@d`) and confirm the expected daily risk volume.

The rule is risk-only (no notable). Enabling it is a separately approved change.
