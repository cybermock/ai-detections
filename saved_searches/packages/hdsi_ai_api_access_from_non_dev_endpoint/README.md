## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds hosts that call **AI provider APIs**, such as `api.openai.com`, `api.anthropic.com`, AWS Bedrock, GCP Vertex AI, Azure OpenAI, DeepSeek, Deepgram or OpenRouter, even though nothing else suggests a developer works on them. A developer laptop or build server calling an LLM API is normal. A kiosk, line-of-business workstation, office PC or production server doing the same is usually a script, an agent, a browser extension or desktop tool using a personal API key, or a third-party product that sends data to an AI vendor. Each of those moves data outside the sanctioned AI channels. LLM-enabled malware uses the same APIs. The rule creates risk on `src` (system) and, when exactly one firewall or proxy user is seen for that source, on `user`. It creates no notable.

v1.0 read only the Web data model and treated every source **missing** from the asset inventory as a non-developer endpoint (`isnull(src_category)`). Where inventory was thin, every source fired. Its `tstats` split by `Web.site`, which drops every event where `site` is empty, so on the one validation tenant whose proxy logs carried AI API hostnames it returned nothing. Its `dev|developer|engineering|build` category regex also matched the common `devices` category. v1.1 changes the logic. It decides "developer" by what the host does (package registries, IDE and code-assistant traffic). It reads DNS and firewall App-ID as well as proxy logs. It drops hosts that cannot be classified.

### Prerequisites
Any one data path is enough. The three data models are read by chained `tstats prestats=t append=t` calls in the main pipeline, not by `append` subsearches, so no branch is cut off by the 60 s subsearch time limit or the subsearch row cap. A missing data model only adds no rows (`data_prereqs` op `OR`).

| Data | Fields used | What it adds | If absent |
|---|---|---|---|
| `Network_Resolution` (accelerated), client-facing DNS logs | `query`, `src` | API hostnames, consumer-app hostnames and developer-tooling hostnames per client. This is the most portable path. | No user attribution from DNS in any case |
| `Network_Traffic` (accelerated) from an NGFW with App-ID (PAN-OS style) | `app`, `src`, `user`, `action` | `anthropic-api-*`, `openai-api*`, `deepseek-api*` sessions, the matching consumer apps, developer App-IDs (`github-base`, `gitlab-base`, ...), the firewall User-ID, and whether the session was blocked | Firewalls that put only protocol or port in `app` contribute nothing |
| `Web` (accelerated) from an egress proxy | `url_domain` or `site` (host name), `src`, `user` | The same hostnames from proxy logs, with the proxy user | SSE/CASB feeds that put only an app name in `site` (for example "OpenAI") add nothing here, because API traffic has no distinct app name |

- `src` must be the **client**. DNS logs that show a resolver or forwarder as the client are excluded by asset category (`..._resolver_categories`). Add other resolver IPs to `..._filter`.
- ES asset inventory (`asset_lookup_by_str`, matched on `ip`) supplies `src_asset` and `src_category`. With the default `..._require_known_asset = 1`, a source with no inventory match and no user is dropped.
- Uses `ai_domains_filter` (provider, `usage_type`, `severity_weight` from `ai_provider_domains`), `ai_unsanctioned_filter(3)` (approvals in `ai_sanctioned_entities`) and `ai_risk_multiplier` (identity `bunit` sensitivity) from `hdsi_ai_rba_common`, which is a required prerequisite package.

### How it works
- **Collect (one daily window):** three chained `tstats prestats=t` calls over DNS (`query` by `src`), Web (`url_domain`/`site` by `src`, `user`, with `fillnull_value` so empty `site` keeps the row) and Network_Traffic (`app` by `src`, `user`, `action`), merged by one `stats` into `src`, `user`, `ai_domain`, `action`, `evidence_type`. Each is pre-filtered inline by three hostname macros: AI API endpoints, consumer AI app front-ends and developer-tooling names. DNS names are listed with and without the trailing root dot. Every branch is read completely: the developer and consumer-app checks need all of a host's evidence for the day, and a truncated branch would both miss API rows and report hosts whose suppressing evidence was cut off.
- **Developer fingerprint:** a source that resolves or connects to any developer-tooling endpoint in the window gets `dev_tooling=1` and is not reported. The endpoints are npm, PyPI, Conda, Go, Maven, Gradle, crates.io, RubyGems, NuGet, Docker Hub, GHCR, Terraform, the VS Code and JetBrains update services, and the GitHub Copilot and Cursor APIs, plus developer App-IDs.
- **Provider resolution:** App-IDs are mapped first by `..._app_id_map`. Then every row goes through `ai_domains_filter`, which resolves DNS and Web hostnames and keeps the App-ID mapping (an App-ID is not a hostname). Only `usage_type="api"` rows are candidates. The Bedrock, Vertex AI, Azure OpenAI, Azure AI Foundry, Azure AI Services and SageMaker cloud patterns resolve to `api`.
- **Consumer-app check:** when the same source also reached that provider's own chat app in the window (`claude.ai`, `chatgpt.com`, `gemini.google.com`, App-ID `claude-base`, `openai-chatgpt`, ...), the API row for that provider is dropped. The desktop and web apps call the API hostname themselves, so the API call is not independent evidence. Web-access detections already cover those users.
- **Exclusions:** `..._excluded_providers` (GitHub Copilot, Cursor, Suno), `..._sanctioned_endpoints`, resolver and developer asset categories, `..._dev_sources`, and per-user, per-host and per-group approvals in `ai_sanctioned_entities` (the group is the user's identity `bunit`).
- **Asset context:** the ES asset `category` is lower-cased, split on newlines and pipes, and de-duplicated, so a category that arrives as one multi-line string reads as `a|b|c` in the risk message. A source in the inventory without a category shows `no asset category`; a source outside it shows `not in asset inventory`.
- **Risk objects:** placeholder users (`unknown`, `-`, empty) are nulled. Results are aggregated to **one row per `src`**. `user` is set only when exactly one user was seen. More than `..._max_users_per_src` users means shared egress, and the row is dropped. No row carries an `unknown` risk object.
- **Scoring:** base 20, or 5 when every firewall session was blocked. `risk_score = min(50, round(base x severity_weight x risk_multiplier))` applies to `src` and `user`. `severity_weight` comes from the provider row (1.2 for the main LLM APIs and cloud AI platforms, 1.0 for speech and aggregator APIs, 0.8 for Azure AI Services). `risk_multiplier` comes from the user's identity `bunit` and is 1.0 without a user. The `_risk` literal fallbacks are 24 and 24.
- **Cadence:** daily at 01:45 over the previous calendar day (`-1d@d` to `@d`), suppressed 20 h per `src` and `user` (one row per `src`, so in effect per host). The developer fingerprint and the consumer-app check need a whole day of evidence. A developer does not pull a package every hour.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_api_access_from_non_dev_endpoint_filter` | `()` | Exclusions inside the DNS `tstats` (`DNS.*` names). Add internal resolvers or forwarders that appear as the client |
| `hdsi_ai_api_access_from_non_dev_endpoint_web_filter` | `()` | Exclusions inside the Web `tstats` (`Web.*` names) |
| `hdsi_ai_api_access_from_non_dev_endpoint_app_filter` | `()` | Exclusions inside the Network_Traffic `tstats` (`All_Traffic.*` names) |
| `hdsi_ai_api_access_from_non_dev_endpoint_api_endpoints(1)` | every enabled `api` row of `ai_provider_domains` plus cloud AI patterns | Scan pre-filter only. Add a host here when you add an `api` row to the common lookup |
| `hdsi_ai_api_access_from_non_dev_endpoint_app_endpoints(1)` | `claude.ai`, `claude.com`, `chatgpt.com`, `chat.openai.com`, `gemini.google.com`, `aistudio.google.com`, `chat.deepseek.com`, `chat.mistral.ai`, `grok.com`, `perplexity.ai`, `kimi.com`, `chat.qwen.ai`, `chatglm.cn`, `chat.z.ai` | Consumer front-ends used by the consumer-app check |
| `hdsi_ai_api_access_from_non_dev_endpoint_dev_endpoints(1)` | package, container and IaC registries, VS Code and JetBrains, Copilot and Cursor APIs | Developer fingerprint. Literal names only (also evaluated with `eval ... IN`) |
| `hdsi_ai_api_access_from_non_dev_endpoint_app_ids` | `anthropic-api*`, `openai-api*`, `deepseek-api*`, `claude-*`, `anthropic-claude*`, `openai-chatgpt*`, `openai-base`, `deepseek-chat*` | Firewall App-IDs for AI APIs and their consumer apps |
| `hdsi_ai_api_access_from_non_dev_endpoint_dev_app_ids` | `github-base`, `github-copilot*`, `github-downloading`, `gitlab-base`, `bitbucket-base`, `git-base`, `visual-studio*`, `docker*`, `jetbrains*` | Developer App-IDs. `github-pages` and `ssh` are absent on purpose |
| `hdsi_ai_api_access_from_non_dev_endpoint_app_id_map` | `eval` mapping | App-ID to `provider`, `usage_type`, `severity_weight`, `enabled`, `app_dev_hit`. Rows without `app` pass through unchanged |
| `hdsi_ai_api_access_from_non_dev_endpoint_excluded_providers` | `"GitHub Copilot","Cursor","Suno"` | Providers never reported. Use `"__none__"` to report all |
| `hdsi_ai_api_access_from_non_dev_endpoint_sanctioned_endpoints` | `"__none__"` | Endpoints approved for everyone, wildcards allowed, e.g. the organisation's own `contoso-*.openai.azure.com` or Bedrock region |
| `hdsi_ai_api_access_from_non_dev_endpoint_dev_categories` | `"dev(?!ice)\|engineer\|build\|jenkins\|sandbox\|non-?prod"` | Asset-category regex for developer and build assets |
| `hdsi_ai_api_access_from_non_dev_endpoint_resolver_categories` | `"domain.?controller\|dns\|resolver\|forwarder"` | Asset-category regex for DNS servers that appear as the client |
| `hdsi_ai_api_access_from_non_dev_endpoint_dev_sources` | `false()` | Eval expression for developer networks the inventory does not label, e.g. `cidrmatch("10.50.0.0/16",src)` |
| `hdsi_ai_api_access_from_non_dev_endpoint_require_known_asset` | `1` | 1 drops sources with no inventory match and no user. Set 0 only if the inventory does not cover client IPs |
| `hdsi_ai_api_access_from_non_dev_endpoint_max_users_per_src` | `3` | Shared-egress guard (see Threshold) |
| `hdsi_ai_api_access_from_non_dev_endpoint_unreliable_src` | `false()` | Eval expression for roaming or shared addresses. Matching rows without a user are dropped |
| `hdsi_ai_api_access_from_non_dev_endpoint_customizations` | `search *` | Post-aggregation hook (fields: `src`, `src_asset`, `src_category`, `user`, `user_display`, `provider_list`, `providers`, `endpoint_sample`, `evidence_type`, `event_count`, `allowed`, `base_score`, `severity_weight`, `risk_multiplier`, `risk_score`) |
| `hdsi_ai_api_access_from_non_dev_endpoint_risk_score` | `search *` | Last pipe. Override `risk_score` (≤100) here |

Per-host, per-user and per-group approvals go in `ai_sanctioned_entities` (common package), keyed `<src, user or bunit>|<provider>`. For example, a production server that calls Vertex AI for an approved application is `<server ip>|gcp vertex ai`. Use `..._sanctioned_endpoints` when an endpoint is approved for everyone.

### Threshold
`hdsi_ai_api_access_from_non_dev_endpoint_max_users_per_src` defaults to 3. It only matters where the firewall or proxy supplies `user`. A workstation shows one user a day, occasionally two. A NAT pool, explicit proxy, VDI host or terminal server shows many. Measure over full days and set the value just below the first source count that belongs to known shared infrastructure:

```spl
| tstats summariesonly=t allow_old_summaries=t dc(All_Traffic.user) as users from datamodel=Network_Traffic
    where `hdsi_ai_api_access_from_non_dev_endpoint_app_ids` All_Traffic.user=* NOT All_Traffic.user="unknown"
    by All_Traffic.src _time span=1d
| stats max(users) as max_users_per_day by All_Traffic.src
| stats count as srcs by max_users_per_day
| sort max_users_per_day
```

For proxy data, run the same SPL over `Web` with `Web.user` and `Web.src`.

### Known false positives / Limitations
- **Embedded vendor AI on shared kiosks and line-of-business workstations.** On Tenant A, 17 of 36 daily rows were `api.deepgram.com` (speech-to-text) from shared kiosks and line-of-business workstations. That is almost certainly a third-party application that sends audio to its AI vendor. The detection is correct, and it is the kind of data flow governance wants to see once. After review, approve it with `..._sanctioned_endpoints` (`"api.deepgram.com"`) or per-host entries.
- **Production servers calling cloud AI.** On Tenant A, 6 application servers called GCP Vertex AI (2 of them also Azure AI Services) all day. These are integrations, not users. Approve them per host in `ai_sanctioned_entities` (`<ip>|gcp vertex ai`).
- **Consumer apps call API hostnames.** On Tenant B, 258 of 373 hosts that resolved `claude.ai` also resolved `api.anthropic.com`. That included 81 of 140 hosts with no developer tooling. On Tenant A, 555 of 700 `anthropic-api-*` App-ID sources (79%) also showed a Claude consumer App-ID the same day. Without the consumer-app check, Claude desktop and web users would dominate the output. The check means an API key used from a host that also runs the provider's chat app is not reported for that provider. `chatgpt.com` users almost never resolve `api.openai.com` (5 of about 2,300 on Tenant B), so OpenAI API rows are rarely affected.
- **The developer fingerprint is generous on purpose.** Any one developer-tooling hostname in the day classifies the host as a developer endpoint, including a VS Code update check. On the software-heavy Tenant B, 262 of 377 API sources showed developer tooling. A non-developer who has VS Code installed is not reported. Narrow `..._dev_endpoints` if that matters more than noise.
- **DNS gives no user.** DNS-only rows raise system risk only. Users appear only where the firewall has User-ID or the proxy authenticates.
- **Roaming DNS security clients.** On Tenant B, 3 of 5 daily rows had a home-network `192.168.x.x` address that the asset inventory had recorded for a laptop. A different laptop could hold that address. Set `..._unreliable_src` (for example `cidrmatch("192.168.0.0/16",src) OR match(src,":")`) on roaming-DNS tenants where these addresses are not corporate LAN ranges.
- **Unknown sources are dropped.** On Tenant A, 158 daily sources (proxy and App-ID addresses outside the inventory, no user) were removed by `..._require_known_asset`. This is the guard against the v1.0 flood. It also means NAT, VPN-pool and unmanaged addresses are not covered here. `hdsi_ai_access_from_unmanaged_device` is meant to cover them, but it is incubating and not released (see [`saved_searches/incubating/hdsi_ai_access_from_unmanaged_device/`](../../incubating/hdsi_ai_access_from_unmanaged_device/README.md)).
- **Runtime.** The full day is read from accelerated summaries in every branch. That took about 230 s on the largest tenant (Tenant A, about 7 billion Network_Traffic and 1 billion DNS events a day), which is fine for a daily schedule but worth placing outside the busiest scheduler window.
- **App-ID coverage is PAN-OS style.** Only `anthropic-api*`, `openai-api*` and `deepseek-api*` are mapped to APIs. `google-gemini-models` and `cohere.ai-base` were seen in validation, but it is not clear whether they are API App-IDs, so they are not mapped. Add vendor-specific values to `..._app_ids` and `..._app_id_map`.
- **DNS servers as clients.** On Tenant A, 18 of 45 sources that resolved AI API names were domain controllers forwarding for clients. Most of them also resolve developer-tooling names, so the developer check removes them first; `..._resolver_categories` removed the remaining 3. Inventories that do not label resolvers need their IPs in `..._filter`.

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09. The v1.1 runs used the scheduled window (`-1d@d` to `@d`), so the row count equals one day of risk events. Removal counts are distinct sources at the first exclusion that applies, in pipeline order.

| Tenant | Data paths with AI API traffic | Parses (search + 4 drilldowns) | v1.0 rows (4 h) | v1.1 rows (1 day) | Score mix | Notes |
|---|---|---|---|---|---|---|
| A | Proxy (`url_domain`, empty `site`), NGFW App-ID with User-ID, partial DNS (mostly via domain controllers) | OK | 0 | 36 (about 230 s) | 10 at 24, 21 at 20, 3 at 16 (Azure AI Services), 2 at 6 (all sessions blocked) | Deepgram 17, GCP Vertex AI servers 6 (2 also Azure AI Services), Anthropic 5, Azure AI Services 3, ElevenLabs 3, OpenAI 1, OpenRouter 1. Evidence: proxy 29 (11 also DNS), App-ID 6, DNS only 1. 14 rows carry a user. Removed: 195 developer-tooling, 1,214 consumer-app, 3 resolver and 158 unclassifiable sources |
| B | DNS only (roaming DNS security service, trailing-dot names) | OK | 0 | 5 (about 75 s) | 5 at 24 | Anthropic 4, AWS Bedrock 1. Removed: 262 developer-tooling, 104 consumer-app and 6 unclassifiable sources (out of 377 sources with AI API, AI app or developer-tooling names) |
| C | DNS, small App-ID without User-ID | OK | 0 | 1 (about 9 s) | 1 at 24 | AWS Bedrock and SageMaker from a workstation. Removed: 17 developer-tooling, 4 consumer-app and 4 unclassifiable sources |
| D | None (DNS server logs without AI API names, no App-ID, inbound-only web logs) | OK | 0 | 0 | none | No data path. Expected silence |

No FATAL, ERROR or subsearch messages on any tenant. An earlier v1.1 draft joined the Web and App-ID branches with `append` subsearches; on Tenants A and B those hit the 60 s subsearch time limit and were silently auto-finalized, so the result depended on search-head load (the truncated Tenant A run reported 40 rows against 36 on complete data). The chained `tstats prestats=t append=t` form reads every branch completely; on Tenant C its merged DNS and App-ID row counts matched standalone `tstats` exactly. v1.0 returned 0 rows everywhere: the proxy that carries API hostnames leaves `site` empty, and the other tenants have no egress proxy. All four drilldowns filter `src` inside `tstats`.

Expected daily volume, at most one event per host per day at 5 to 24 points (up to 50 with the multiplier): Tenant A about 36 (about 13 after approving the embedded speech vendor and the Vertex AI servers), B about 5, C about 1, D none.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:

1. Confirm that at least one data path exists. DNS needs client-level queries. App-ID needs `anthropic-api-*`/`openai-api*` values. A proxy needs AI API hostnames in `url_domain` or `site`.
2. Confirm that the ES asset inventory matches client IPs, label resolvers and developer assets (or extend `..._resolver_categories`, `..._dev_categories`, `..._dev_sources`), and add resolver IPs to `..._filter`.
3. Run the search once over the scheduled window (`-1d@d` to `@d`). Review the sources, then approve known integrations with `..._sanctioned_endpoints` or `ai_sanctioned_entities`.
4. Derive `..._max_users_per_src`. On roaming-DNS tenants, decide whether to set `..._unreliable_src`.

The rule is risk-only (no notable). Enabling it is a separately approved change.
