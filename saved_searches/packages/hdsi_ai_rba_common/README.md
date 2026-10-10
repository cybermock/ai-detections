## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This package holds the shared macros and lookups that every HDSI AI RBA package depends on. It contains no saved searches and creates no risk or notables by itself. It does four things: it resolves network evidence (hostnames, URLs, DNS answers, SSE/CASB app names, firewall App-IDs) to an AI provider, removes approved AI use, resolves AI tools from process names, and scales risk by identity sensitivity. Deploy it before any `hdsi_ai_*` or `hdsi_rba_ai_*` package and keep its lookups current. The provider registry decides what the Web, DNS and firewall detections can see.

### Prerequisites

- **Splunk Enterprise Security 8.x.** `ai_risk_multiplier` and `ai_unsanctioned_filter` read the ES `identity_lookup_expanded` lookup (`identity` key; `bunit`, `category` and `priority` fields). ES identities in all four validation tenants have no `department` field, so `bunit` is the supported key.
- **Every CSV in `lookups/` must be deployed, together with its `transforms.conf` stanza.** A `| lookup` on an undefined lookup is a fatal search error. In that case every dependent detection fails, not just one.
- No data model is required by this package. The dependent packages declare their own `data_prereqs`.

### How it works

#### `ai_domains_filter`: the provider resolver

Callers set **`ai_domain`** (and optionally **`ai_input_type`**) and then pipe `` | `ai_domains_filter` ``. The macro works in this order:

1. **Normalise** `ai_domain`. **Only the first value of a multivalue field is evaluated**; a later AI value in the same row is silently lost (verified: `notion.so,chatgpt.com` as one multivalue row returns nothing). Callers whose source field can be multivalue (`url`, `query`, `dest`, email recipient domains) must `| mvexpand ai_domain` before the macro, and count events before the expansion so totals are not doubled. Then:
   - lowercase and trim;
   - strip a URL scheme and anything after `/ ? #`;
   - strip a leading `*.`, a `:port`, any trailing dots (DNS answers such as `chatgpt.com.`) and a leading `www.`/`wwwN.`;
   - collapse whitespace in app names.

   `ai_domain` is **rewritten** to this normalised form.
2. **Exact match** against `ai_provider_domains.domain`. An exact row always wins, including `enabled=0` rows, so a single host can be switched off.
3. **Subdomain match** against the immediate parent, the grandparent and the registrable base (last two labels). A parent row is used **only if it has `match_subdomains=1`**. The most specific match wins. For example, `bzrcdn.openai.com` resolves through its own row, `foo.chatgpt.com` through `chatgpt.com`, but `msgstore.www.notion.so` does not resolve through `notion.so`.
4. **Cloud AI endpoint patterns.** These cover regional and per-resource hosts that cannot be listed one by one:
   - AWS Bedrock: `bedrock*.<region>.amazonaws.com`
   - GCP Vertex AI: `[<region>-]aiplatform.googleapis.com`, including `_grpclb._tcp.` SRV names
   - Azure OpenAI: `*.openai.azure.com`
   - Azure AI Foundry: `*.services.ai.azure.com`
   - Azure AI Services: `*.cognitiveservices.azure.com` (provider `Azure AI Services`). Many Azure OpenAI and Foundry resources are reached here, but so are Speech, Translator, Vision and Document Intelligence, so this pattern is medium confidence and gets `severity_weight=0.8`.
   - AWS SageMaker: `*sagemaker.<region>.amazonaws.com`

   These matches get `usage_type=api` and `severity_weight=1.2` (0.8 for Azure AI Services). Exact-name tstats pre-filters in the detections do **not** see these patterns; a pre-filter must add `bedrock*.amazonaws.com` / `*aiplatform.googleapis.com` terms itself.
5. **App-name match.** This step covers SSE/CASB proxies that put an application name in CIM `Web.site` (for example, Netskope `ChatGPT`, `Google Gemini`), Palo Alto App-IDs in `Network_Traffic.app` (for example, `openai-chatgpt`, `claude-base`) and IdP/SSO application labels. The value is looked up in `ai_provider_apps.app_name` when **one** of these is true:
   - the caller set `ai_input_type="app"`. Since v1.1 this also applies to dotted App-IDs such as `otter.ai-base`, `cohere.ai-base` and `fireflies.ai-base`, which look like hostnames and were never resolved before;
   - the value is not a hostname and contains a space (no hostname has one);
   - the value is not a hostname and equals the row's own `site` or `app` field (the macro checks provenance automatically, so the standard Web calling pattern needs no change).

   A caller can set `ai_input_type="host"` (or `"dns"`) to disable the step completely. Without this gate a single-label DNS query such as `claude.`, `cursor` or `gamma` (internal hostnames, search-suffix queries) would be reported as AI app use; one such query (`claude.`) was seen live in Tenant B. Single-word names are therefore never matched from a DNS `query` field. Domain matching (steps 2-4) always runs first, so `ai_input_type="app"` never hides a real hostname match.
6. **Output.** The macro sets `provider`, `usage_type`, `severity_weight`, `enabled`, `ai_match` (`exact` | `subdomain` | `cloud_pattern` | `app_name`) and, since v1.1, **`ai_traffic_class`**: `interactive` (product or API use), `background` (telemetry, experimentation, sign-in refresh and updater hosts that installed apps poll without a user action) or `site` (vendor website, documentation or model catalogue). It comes from the registry `traffic_class` column of the matched row; cloud patterns and app names are always `interactive`. It then keeps only `enabled=1` rows. Temporary `_aid_*` fields are removed.

Calling pattern for a Web detection. `fillnull_value` is required because tstats drops a row when any `by` field is null: SSE app-name rows have no `url_domain` (Tenant C) and firewall URL rows have no `site` (Tenant A):

```text
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count ... from datamodel=Web where (Web.url_domain=* OR Web.site=*) by Web.user Web.src Web.url_domain Web.site
| rename Web.* as *
| eval ai_domain=lower(coalesce(nullif(url_domain,"unknown"), nullif(site,"unknown")))
| `ai_domains_filter`
| where ai_traffic_class!="background"      (optional: volume and first-seen rules)
```

Calling pattern for a DNS detection. Resolve providers on distinct query names first: the macro runs five lookups plus regexes per row, and a `src` x `query` table on a busy tenant (about 1.1B DNS queries a day in Tenant A) took 250-270 s for a 4h window, close to the scheduler cap. Aggregated by query, the same 1h resolution ran in 25 s on Tenant A:

```text
| tstats summariesonly=t allow_old_summaries=t count from datamodel=Network_Resolution where DNS.query=* by DNS.src DNS.query
| rename DNS.* as *
| eval ai_domain=query, ai_input_type="dns"
| `ai_domains_filter`
```

Calling pattern for Palo Alto App-ID or other application-name data (`Network_Traffic.app`): `` | eval ai_domain=app, ai_input_type="app" | `ai_domains_filter` ``.

#### `ai_unsanctioned_filter(3)`: the approved-use allowlist

Call it as `` `ai_unsanctioned_filter(<user_field>,<system_field>,<provider_field>)` `` with field names (the shipped packages pass `user,src,provider`, `user,dest,provider`, `device_name,src,provider`, `ukey,src,provider` or `user,src,allow_provider`; all keep working unchanged). For every row it builds these keys and looks each one up in `ai_sanctioned_entities.allow_key`:

| Key | Built from |
|---|---|
| `lower(<user>)\|lower(<provider>)` and `lower(<user>)\|*` | the user field |
| `lower(<system>)\|lower(<provider>)` and `lower(<system>)\|*` | the system field |
| `<group>\|lower(<provider>)` and `<group>\|*` | the identity group (below) |
| `*\|lower(<provider>)` | **organisation-wide approval** (new in v1.1). Never `*\|*`: a row with an empty provider is not matched by it |

The **group** is the first non-empty value of `user_group`, `user_category`, `bunit`, the **ES identity `bunit` of the user, looked up by the macro itself** (new in v1.1: first the raw value, then the bare name with `DOMAIN\` and `@suffix` removed), and finally `category` (legacy fallback; Web rows can carry a URL category there, which is why it now comes last). The value `unknown` is ignored. Group allowlisting therefore works even when the caller never looked up an identity, as long as the user resolves in `identity_lookup_expanded`; where identities carry no `bunit` (Tenants B and D for most users), use a user, system or organisation-wide key instead.

A matching entry is active when `enabled=1` and `expires` is empty or not earlier than today (`YYYY-MM-DD`). Rows with any active match are removed. Since v1.1 the macro ends with `| fields - _allow_*`, so none of its working fields reach risk events (callers that still strip `_allow_*` themselves are unaffected).

#### `ai_risk_multiplier`: identity sensitivity

Reads the field `user` and sets `risk_multiplier` (plus `sensitivity_level` and the legacy alias `_final_multiplier`):

1. Look up `user` in `identity_lookup_expanded`. If nothing matches, look up the **bare name** (lowercased, `DOMAIN\` and `@suffix` removed). Built-in names (`administrator`, `admin`, `root`, `system`, `guest`, `globaladmin`) are never bare-matched, so a local administrator on one host does not inherit a directory admin's identity. In Tenant C, where the Web user is a UPN, no AI user matched directly and 63% matched only by the bare name.
2. Take the identity `bunit`, lowercased; an empty value becomes `general`. Look it up as `department` in `ai_department_sensitivity`: first the whole value, then its **last** path segment, then its **first** path segment (separators `/ \ > | :`). An unmatched value gives 1.0.
3. Multiply by 1.25 when an identity `category` value is the whole word `priv`/`privileged` (or a misspelling ending in `-ged`, optionally followed by `_user`/`_account`), or `priority` is `critical`. Since v1.1 a substring such as `non-privileged` or a privacy-team category no longer counts.
4. Cap the result at 2.0 and round to two decimals.

Use `risk_multiplier`, not `_final_multiplier`, in messages. Fields that start with `_` are dropped from risk events.

#### Other macros

- **`ai_process_filter`.** Looks up `process_name_lc` in `ai_tool_processes` (the caller must create `process_name_lc`). Outputs `tool`, `provider`, `usage_type`, `platform`, `enabled` and, since v1.1, `requires_context`, then keeps `enabled=1`. `requires_context=1` marks generic or colliding names (`fabric.exe` = Microsoft Service Fabric, `lms.exe` = Intel Management Engine, `chat.exe`, `jan`, `llm`, `mods`, `continue`, `zed`, `warp`, `pieces`, `tabnine`, bare `copilot`, `goose`, `crush`, `amp`): corroborate those with `process_path` or the command line before scoring.
- **`ai_process_enrich`** (new in v1.1). The same lookup and outputs as `ai_process_filter` but it keeps every row, for rules that match on command line or image path and only want the tool/provider label. Filter on `enabled` yourself.
- **`ai_prompt_injection_patterns_enabled` and `ai_api_key_patterns_enabled`.** Generating searches that return the enabled rows of their pattern libraries (`pattern_id pattern severity` and `pattern_id provider regex_pattern severity`). Use them at the start of a search or inside a subsearch.
- **`ai_risk_defaults(1)`.** An optional helper that no shipped detection uses. `` `ai_risk_defaults("high_risk_threshold")` `` returns the bare value of `control_name` from `ai_detection_config` as a subsearch. The aggregators read thresholds with `| lookup ai_detection_config control_name ... OUTPUTNEW value`.

### Lookups

| Lookup (transforms stanza) | Key | Columns | Purpose and how to tune |
|---|---|---|---|
| `ai_provider_domains` | `domain` | provider, domain, usage_type, severity_weight, enabled, match_subdomains, notes, source, first_seen, last_verified, confidence, **traffic_class** | AI provider registry, 200 rows. **`match_subdomains=1`** extends a row to every subdomain. Set it only where the entire tree is AI-specific (`chatgpt.com`, `claude.ai`, `cursor.sh`). Use `0` for multi-purpose SaaS bases. Add a host with `enabled=0` to silence it without losing its parent. **`traffic_class`** = `interactive` (default), `background` (weight 0.3: `ab.chatgpt.com`, `bzr`/`bzrcdn.openai.com`, `auth.openai.com`, `downloads.claude.ai`, `gemini.gstatic.com`, Copilot telemetry, QuillBot extension streams) or `site` (`aider.chat`, `ollama.com`, `lmstudio.ai`). |
| `ai_provider_apps` | `app_name` (lowercase) | app_name, provider, usage_type, severity_weight, enabled, source_product, notes, last_verified, confidence | SSE/CASB application names (Netskope, Zscaler, Umbrella, Island), Palo Alto App-IDs (incl. the `-base`/`-post`/`-upload` variants seen live), a FortiGate name and IdP application labels, 105 rows. Add the exact app names your proxy emits, lowercased. To find them: `\| tstats count from datamodel=Web where Web.category="Generative AI" by Web.site`, or `\| tstats count from datamodel=Network_Traffic where All_Traffic.app=*ai* by All_Traffic.app`. |
| `ai_sanctioned_entities` | `allow_key` | entity_type, entity, provider, scope, expires, owner, reason, enabled, allow_key | Approved AI use. `allow_key` = `lower(entity)\|lower(provider)`, `lower(entity)\|*` for all providers, or `*\|lower(provider)` for the whole organisation (`entity_type=group`, `entity=*`, `scope=global`). `entity` is a user, system (src/dest value) or group (`bunit`/category value). The provider must match the `provider` string emitted by the detection (see "Provider names"). Ships with five **disabled** `EXAMPLE_ONLY` rows. Keys are unique: enable or edit the example row rather than adding a second row with the same key, because the first row wins. |
| `ai_tool_processes` | `process_name_lc` | tool, provider, process_name_lc, original_file_name_lc, platform, usage_type, enabled, notes, **requires_context**, **last_verified** | AI CLIs (incl. agentic CLIs: `copilot`, `qchat`, `kiro-cli`, `cursor-agent`, `opencode`, `goose`, `crush`, `qwen`, `amp`), IDE agent runtimes, desktop apps and local LLM runtimes by process name, 109 rows. Versioned binaries (Codex `codex-command-runner-<version>.exe`) and bare `q` cannot be listed as exact keys; match them in the detection. |
| `ai_department_sensitivity` | `department` (matched against identity `bunit`, its last and its first path segment) | department, sensitivity_level, risk_multiplier, notes | Sensitivity per business unit. **Add your real ES `bunit` values** (or their leaf/top segment for hierarchical paths). The shipped keys (`finance`, `legal`, ...) are examples. Values above 2.0 are capped by the macro. |
| `ai_detection_config` | `control_name` | control_name, value, notes | Only `medium_risk_threshold` and `high_risk_threshold` are read (by the two user-risk aggregators; keep medium < high). The other 23 numeric rows are marked `DEPRECATED v1.1` in `notes` with the package macro that replaced each one; they stay so that older health-check control lists do not report them missing. `alert_email_to` ships **empty** on purpose. |
| `ai_mitre_mapping` | `detection_id` | detection_id, mitre_technique_id, mitre_technique_name, mitre_tactic | Reference only, one row per detection and technique, regenerated on 2026-10-09 from each package's `action.correlationsearch.annotations` (87 rows). No search reads it. Regenerate it when an annotation changes. |
| `ai_prompt_injection_patterns` | `pattern_id` | pattern_id, pattern, description, severity, enabled, **last_verified** | Prompt-injection regexes (used with `match()`). |
| `ai_api_key_patterns` | `pattern_id` | pattern_id, provider, regex_pattern, description, severity, enabled, **contextual**, **last_verified** | AI provider API key regexes. `contextual=1` patterns need a keyword next to the token. Do not add a trailing `(?![A-Za-z0-9])` boundary: it turns key-length drift into total misses. |
| `ai_deepfake_tools` | `process_name` | tool_name, process_name, category, risk_level, enabled, notes | Not read by any shipped detection (`hdsi_ai_deepfake_tool_execution_access` matches command lines instead). Kept for reference and for the lookup health check. |

**`usage_type` vocabulary** (`ai_provider_domains`, `ai_provider_apps`): `web`, `api`, `ide`, `cli`, `local_llm`, `model_registry`. Detections filter on these values, for example `hdsi_ai_unsanctioned_web_access` keeps `web` and `hdsi_ai_api_access_from_non_dev_endpoint` keeps `api`, so do not invent new values (a test enforces this). `ai_tool_processes` also uses `desktop_app` and `ide`. **`severity_weight`** runs from 0.3 to 1.2 and scales per-event risk in the detections.

**Provider names are join keys.** `ai_sanctioned_entities`, `provider IN (...)` filters in some detections and risk messages all use the `provider` string. Rename a provider only together with those references. Strings in use today: from the network registries `01.AI, AI21 Labs, AWS Bedrock, Adobe Express, Adobe Firefly, Adobe Sensei, Aider, Alibaba Qwen, Amazon Q, Anthropic, Anyscale, Azure AI Foundry, Azure AI Services, Azure OpenAI, AWS SageMaker, Baidu ERNIE, Blackbox AI, Bolt, ByteDance Doubao, Cartesia, Casetext, Cerebras, Character AI, Chatbase, Cohere, Continue, Coqui, Cursor, Databricks, DeepL, DeepSeek, Deepgram, Descript, Dify, DuckDuckGo AI, ElevenLabs, FakeYou, Fireflies.ai, Fireworks, Fish Audio, GCP Vertex AI, GPT for Work, Gamma, Gemini for Workspace, GitHub Copilot, Google Gemini, Grammarly, Groq, HeyGen, Ideogram, Jasper AI, JetBrains AI, Kiro, Kling, LMArena, LOVO AI, Leonardo, Local LLM, Lovable, Luma, Manus, Meta AI, Microsoft 365 Copilot, Microsoft Copilot, Microsoft Security Copilot, Midjourney, MiniMax, Mistral, Modal, Model Registry, Moonshot, Murf AI, Notion AI, OpenAI, OpenRouter, Otter.ai, Perplexity, Phind, Pieces, Pika, PlayHT, Poe, QuillBot, Replicate, Replit, Resemble AI, Runway, Snowflake Cortex, Sourcegraph, Speechify, Stability AI, Suno, Synthesia, Tabnine, Together, Uberduck, Venice AI, Vercel v0, Voicemod, WellSaid Labs, Windsurf, Writer, You.com, Zhipu AI, xAI`; from `ai_tool_processes` additionally `Amazon` (Amazon Q CLIs), `ByteDance` (Trae), `Codeium` (Windsurf desktop), `Microsoft Copilot` (legacy `gh-copilot`), `Charm`, `Cline`, `Fabric`, `Goose`, `LLM CLI`, `OpenCode`, `Shell GPT`, `Warp`, `Zed`, `aichat`, `tgpt`. The process-side strings `Amazon`, `Codeium` and `Microsoft Copilot` differ from the network-side `Amazon Q`, `Windsurf` and `GitHub Copilot` because several detections compare them literally; to approve such a tool everywhere, add one key per string. Some detections emit their own labels (for example `hdsi_ai_unsanctioned_desktop_app_execution`: `OpenAI, Anthropic, Cursor, Windsurf, ByteDance, Amazon, Perplexity, Pieces, Msty, AnythingLLM`); check the package README before writing an allowlist key.

### Tuning macros

| Macro | Ships as | Purpose |
|---|---|---|
| `ai_domains_filter` | registry and app lookups | Provider resolution; outputs `ai_traffic_class`. Tune the lookups, not the macro. |
| `ai_unsanctioned_filter(3)` | `ai_sanctioned_entities` (examples disabled) | Approved-use allowlist: user, system, group (identity `bunit` looked up automatically) and organisation-wide keys. |
| `ai_process_filter` | `ai_tool_processes`, `enabled=1` only | AI tool process inventory; outputs `requires_context`. |
| `ai_process_enrich` | `ai_tool_processes`, all rows kept | Labels without filtering. |
| `ai_risk_multiplier` | `ai_department_sensitivity`, x1.25 privileged, cap 2.0 | Identity sensitivity scaling. |
| `ai_prompt_injection_patterns_enabled` | enabled rows | Pattern library. |
| `ai_api_key_patterns_enabled` | enabled rows | Pattern library. |
| `ai_risk_defaults(1)` | subsearch helper | Optional. Unused by shipped detections. |

**Typical tuning steps:**

- **Allowlist sanctioned AI.** Per user: `user,jdoe@example.com,OpenAI,provider,2027-06-30,security,ChatGPT Enterprise seat,1,jdoe@example.com|openai`. Per business unit: `group,engineering,GitHub Copilot,group,2027-06-30,security,licensed,1,engineering|github copilot`. **For the whole organisation** (a company-wide licence): enable the example row `*|microsoft 365 copilot`, or add for example `group,*,GitHub Copilot,global,,security,enterprise licence,1,*|github copilot`.
- **Microsoft 365 Copilot ships disabled (opt-in).** Microsoft Message Center **MC1462915** (published 2026-08-27) redirects every user from `m365.cloud.microsoft` to `copilot.cloud.microsoft`: first wave early September 2026, remaining and previously blocking organisations in October and early November 2026. After that rollout the Copilot host *is* the Microsoft 365 web home page, so treating it as AI use would make every Office user an "AI user" and fire every Web and DNS detection on ordinary Office use. Live 1h DNS in the validation tenants already showed 1,468 / 204 / 16 distinct sources on `copilot.cloud.microsoft` (Tenants C / B / A) against 4,730 / 1,131 / 237 on `m365.cloud.microsoft`. The rows marked `OPT_IN_M365_COPILOT` in `notes` therefore ship `enabled=0`: domains `copilot.cloud.microsoft` and `m365copilotapp.svc.cloud.microsoft` (both with subdomains), and app names `microsoft 365 copilot`, `ms-office365-copilot`, `ms-office65-copilot-upload` (vendor spelling), `ms-office365-copilot-upload` and, since v1.1, the Netskope app **`microsoft copilot studio`**: Netskope attaches that label to M365-embedded traffic, which showed as a daily 55-67 MB near-zero-response connection for most users in Tenant C. Copilot Studio itself stays visible through `copilotstudio.microsoft.com` and the PAN App-IDs `ms-copilot-studio`/`ms-copilot-studio-post`. Set the opt-in rows to `enabled=1` only if the organisation has not licensed or approved Microsoft 365 Copilot and wants to see that use. Distinct Copilot products (Copilot for Finance, Security Copilot and consumer `copilot.microsoft.com`/`copilot.com`) stay enabled.
- **Gemini in Google Workspace ships disabled (opt-in)** for the same reason: rows marked `OPT_IN_WORKSPACE_GEMINI` (`appsgenaiserver-pa.googleapis.com`, `appsgenaiserver-pa.clients6.google.com`, App-ID `google-workspace-duet-ai`). The PAN App-ID `google-gemini` is also ambient in some tenants (tens of thousands of users a day in Tenant A); threshold or sanction it.
- **Background traffic.** Volume, first-seen and burst rules should drop or down-weight `ai_traffic_class="background"`; presence rules can keep it (it proves an installed client). Add hosts you find to be background as their own rows with `traffic_class=background` rather than keeping a regex in a package.
- **Other sanctioned enterprise assistants** (GitHub Copilot, Security Copilot) were the next highest-volume AI traffic in the validation tenants. Allowlist them by group or organisation-wide, or set `enabled=0` in both registries if the whole organisation is licensed.
- **API integration servers.** The new Anthropic/OpenAI/DeepSeek API App-IDs (`anthropic-api-base`, `openai-base`, `deepseek-api` ...) expose server-to-API uploads of several GB a day in Tenant A. Sanction those servers by system key before enabling the upload-volume detections.
- **Opt in to the shipped-disabled rows** (`notion.so`, `grammarly.com`, `app.snowflake.com`, `accounts.cloud.databricks.com`, Adobe Spark/Sensei app names) only if ordinary use of those products should count as AI use.
- **Hierarchical business units.** If your `bunit` values are paths (`Corp/Finance/AP`), add the leaf (`ap`) or top segment (`corp`) to `ai_department_sensitivity`; middle segments are not matched. In Tenant A most identities carry hierarchical paths and none matched the shipped keys, so every multiplier there is 1.00 until this is done.

### Shared guidance for detection authors

These points came up in several packages during validation; they are not macro behaviour but every AI package depends on them.

- **ES asset lookups.** `asset_lookup_by_str` is keyed by `asset`, `ip`, `dns`, `mac` or `nt_host` (there is no `key` field; `key as src` is a fatal error in all four tenants). `asset_lookup_by_cidr` must be matched with `asset as <ipfield>` (`ip as <ipfield>` never matches a CIDR row: 0/20 versus 20/20 live). Many inventories carry broad RFC1918 CIDR blocks, so a CIDR match does not prove a known or managed device.
- **Backslashes in drilldowns.** `DOMAIN\user` values lose their backslash inside a quoted SPL term, so `risk_object="$risk_object$"` or `user="$user$"` returns nothing for them (0 of 3 raw versus 3 of 3 with the backslash replaced by `*`, Tenant A, where most users are `DOMAIN\user`). Emit a drilldown-safe field such as `replace(user,"[\\\\\"]","*")` and use it in the drilldown.
- **`fillnull_value` in drilldowns too.** A drilldown tstats that groups by `Web.site` returns nothing in Tenant A (no `site`) unless it sets `fillnull_value`.
- **Placeholder users.** Besides `unknown`, firewall user fields carry placeholders such as `Web browser`; null them before they become a risk object.
- **Non-human accounts.** Codex on Windows runs agent commands as local `CodexSandboxOffline`/`CodexSandboxOnline` accounts; treat them, `SYSTEM`, `root`, service accounts and `machine$` names as non-personal in process-based rules.
- **Netskope application events** (`from_user`, `instance_id`, `sanctioned_instance`) are not in the CIM Web model; only `site`/`app`/`category` reach the detections.
- **`append [...]` subsearches** silently truncate at 50,000 rows and auto-finalize after 60 s. Combine large tstats branches with chained `tstats prestats=t append=t` calls instead.
- **Short acceleration ranges.** One validation tenant accelerates Web and Network_Traffic with `earliest_time=-1w`; baseline rules that look back more than 7 days with `summariesonly=t` get truncated history there.

### Known false positives / Limitations

- **Embedded AI in multi-purpose SaaS.** Notion AI, GrammarlyGO, Replit Agent, Adobe Express and Descript use the same hosts as the base product, so domain evidence cannot separate AI use from ordinary use. They ship disabled (Notion, Grammarly), exact-match only (Replit, Writer, Modal, Anyscale) or at a low weight (Descript 0.6, Kaggle 0.6).
- **DNS is device evidence, not user intent.** Desktop apps and IDE extensions poll their backends. The `background` rows mark the known polling hosts (in a 1h DNS sample they were the bulk of the new-row hits: Tenant B 2,304 queries from 262 sources), but other polling still exists, so the DNS detection must threshold and aggregate.
- **OpenRouter and Anthropic API hosts are shared.** `openrouter.ai` serves both the API and the chat UI, and the Claude desktop and web apps resolve `api.anthropic.com`; hostname evidence alone does not prove programmatic use.
- **CNAME chain names do not resolve.** Examples are `chat.openai.com.cdn.cloudflare.net` and `*.azurefd.net` Copilot front doors. The original query is normally logged too, so coverage is not lost.
- **Regional endpoints outside the cloud patterns** (Amazon Q `q.<region>.amazonaws.com`, CodeWhisperer) are listed for `us-east-1` only.
- **Lookalike hosts are not matched.** The macro never does substring matching on provider names, so `openai.<unrelated>.com` is ignored. Lookalikes of this kind were seen in inbound web logs in one tenant.
- **Rows that could not be re-verified** keep `source=threat_intel` with their original `last_verified` date (about 40 enabled rows are older than 90 days: most PRC providers and several voice/video vendors). Review them before relying on them. In `ai_tool_processes`, `ai_api_key_patterns` and `ai_prompt_injection_patterns`, rows not reviewed in this revision carry `last_verified=2026-03-04` (the package creation date) so that the lookup staleness check reports them honestly.
- **Pooled provider labels.** `Model Registry` covers Hugging Face, ModelScope, Kaggle and Civitai; first-seen and rarity rules count them as one provider. Splitting the label would break existing allowlist keys.
- **Azure AI Services is broad.** `*.cognitiveservices.azure.com` covers every Azure AI service, so a match proves Azure AI API use, not LLM use. It carries `severity_weight=0.8`.
- **Multivalue `ai_domain`.** Only the first value is resolved; `mvexpand` first (see step 1).
- **Single-word app names** from sources other than `site`/`app` need `ai_input_type="app"`; otherwise they are deliberately ignored. Dotted App-IDs always need it.
- **App names are vendor-specific and change.** Only the Netskope names and PAN App-IDs observed live and the App-IDs published by the vendor are `high` confidence. Island, FortiGate and IdP labels and other display names are `medium`.

### Validation

Read-only searches against four production ES tenants, run on 2026-10-09. Tables show provider names and aggregate counts, not customer identifiers.

**Macro contracts (this revision)**

| Check | Tenant A | Tenant B | Tenant C | Tenant D |
|---|---|---|---|---|
| `ai_domains_filter` unit cases (22: dotted App-IDs with and without `ai_input_type="app"`, `-base` App-IDs, Island names, background/site classes, Suno CDN vs API, Bedrock pattern, JetBrains backend, opt-in M365/Workspace/Copilot Studio rows, single-label DNS) | 22/22 as expected | 22/22 | 22/22 | 22/22 |
| `ai_unsanctioned_filter` unit cases (12: org-wide key, `*\|*` ignored, expired and disabled org rows, case-insensitive provider, group via `bunit` with a URL `category` present, legacy `category`, `bunit=unknown`, user key) | all as expected; no `_allow_*` field left | all as expected | all as expected | all as expected |
| Web users (up to 3,000, 4h) matched in `identity_lookup_expanded` | `DOMAIN\user` (60%): 81% direct; UPN (40%): 6% direct; bare-name fallback adds 4 users | bare names: under 1% | UPN: 0% direct, **63% only by bare name** | no Web users |
| `ai_risk_multiplier` on those users | all 1.00 (hierarchical `bunit` paths not mapped) | 2 users 1.25 (privileged) | 1.20 for 380, 2.00 for 52 (all 1.00 before the fallback) | n/a |
| Identity `category` privileged rule | whole-word rule drops 2 of 355 former substring matches (a privacy-team category); misspelt "privileged" still counts | no change | no change | no change |
| New registry rows in DNS, 1h | OpenAI background hosts (65 queries, 24 sources), Chatbase | OpenAI background (2,304 queries, 262 sources), Claude updater, Chatbase, DuckDuckGo AI, Gemini Code Assist | OpenAI background (97 queries), `ws.chatgpt.com` | none |
| Dependent packages, parse incl. drilldowns (`hdsi_ai_unsanctioned_web_access`, `hdsi_ai_dns_queries_to_ai_domains`, `hdsi_ai_local_llm_framework_execution`) | OK | OK | OK | OK |
| `hdsi_ai_unsanctioned_web_access` real run (auto 4h window) with the new filter | 254 rows, 20 s | 0 rows, 36 s | 0 rows | 0 rows |

**Resolver and registry (earlier run the same day)**

| Check | Tenant A | Tenant B | Tenant C | Tenant D |
|---|---|---|---|---|
| Recall: 46 AI inputs through `ai_domains_filter`¹ | 43/46; the 3 misses are bare single-word app names with no `site`/`app` provenance (`ChatGPT`, `Anthropic`, `openai-chatgpt`), skipped by design | same | same | same |
| Noise: 53 non-AI, multi-purpose or opt-in inputs² | 3 intended exact matches only (`replit.com`, `writer.com`, `modal.com`) | same | same | same |
| M365 Copilot opt-in rows, real DNS 1h | 0 queries survive | 0 | 0 | none present |
| M365 Copilot opt-in rows, real Web 4h | 1,195 events no longer reported | none present | 8,576 app-name events no longer reported | none present |
| AI names in DNS, 24h (Network_Resolution) | Present: OpenAI, Gemini, Anthropic, Copilot, Vertex AI, Perplexity, xAI, QuillBot | Heavy (trailing-dot answers): OpenAI, GitHub Copilot, Anthropic, Cursor, Gemini, M365 Copilot, Manus, Ollama | Present: GitHub Copilot, M365 Copilot, OpenAI, Cursor, Gemini, Anthropic, Lovable, Suno | None in 24h |
| AI in the Web data model, 4h | Firewall URL logs (`url_domain`), led by OpenAI, GitHub Copilot, Anthropic, Gemini, QuillBot | Mostly inbound server logs; small proxy slice | App names only in `Web.site` (`url_domain` empty) | None (inbound IIS) |
| Real DNS 1h, resolved on distinct queries | 15 providers; 25 s | 21 providers; 2 s | 18 providers; 4 s | 0 |

¹ Recall inputs are real hostnames, DNS answers with trailing dots, wildcards, URLs, `host:port`, SRV names, cloud regional endpoints, Netskope app names and PAN App-IDs.

² Noise inputs include `notion.so`, its subdomains, `grammarly.com`, `Grammarly`, `Adobe Spark`, `m365.cloud.microsoft`, CNAME chain names, `*.lovable.app`, Snowflake/Databricks hosts, lookalike domains, `gemini`, the M365 Copilot opt-in hosts and app names, and single-label DNS names (`claude.`, `cursor`, `gamma`, `poe`, `suno`, `replicate`, `openai`, `grok`, `lovable`, `phind`, `murf`, `deepgram`, `ideogram`, `chatgpt`, `anthropic`).

### Deployment

The package ships with `enable_alerting: false` and contains no scheduled searches. It is not risk-generating content, but every AI package depends on it. Deploy it first, then complete these steps before enabling any dependent detection:

1. Map `ai_department_sensitivity` to the tenant's `bunit` values (or their leaf/top segments).
2. Load the tenant's sanctioned AI use into `ai_sanctioned_entities`, including organisation-wide licences (`*|<provider>`) and API integration servers.
3. Add the tenant proxy's and firewall's AI app names to `ai_provider_apps`.
4. Decide on the opt-in rows (`OPT_IN_M365_COPILOT`, `OPT_IN_WORKSPACE_GEMINI`).

Lookup changes alter what every dependent detection reports. Review them like detection changes, and deploy them as one separately approved change.
