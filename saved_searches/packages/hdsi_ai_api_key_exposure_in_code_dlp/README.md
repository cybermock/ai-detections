## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule detects AI provider API keys written in clear text to places Splunk can read. The key formats it recognises are listed under [Key coverage](#key-coverage). The main source is endpoint process command lines (CIM `Endpoint.Processes`), for example `curl -H "Authorization: Bearer sk-proj-…"`, `setx OPENAI_API_KEY …` or `docker run -e HF_TOKEN=hf_…`. It also reads code-repository, DLP and secret-scanner logs when a tenant ingests them. A key in a command line can be read by local administrators, the EDR console, Splunk users and shell history, so the key should be treated as compromised and rotated. The rule emits risk on the user and on the exposing host. It does not create a notable event. The key itself is never copied into the risk event; the event carries only the provider, the last 4 characters and a count of distinct SHA-256 hashes.

### Prerequisites

- **CIM `Endpoint.Processes`, accelerated, with the full command line in `Processes.process`, plus `Processes.dest` and `Processes.user`.** Sources include Sysmon EID 1, Windows 4688 with command-line auditing, and EDR process telemetry. Without command lines the main path returns nothing. Coverage of Linux and macOS is limited: `export VAR=…` is a shell builtin and does not create a process.
- **Optional raw log path**, selected by `hdsi_ai_api_key_exposure_in_code_dlp_log_sources`: sourcetypes for GitHub, GitLab, Bitbucket, DLP, code review and secret scanners. It reads `_raw`, so it only finds keys that the product writes into the event. The CIM `DLP` data model is not used.
- **Common package `hdsi_ai_rba_common`.** This rule uses `ai_api_key_patterns_enabled` (lookup `ai_api_key_patterns`, the regex library, including AK-021 and AK-022 added in the current common release) and `ai_risk_multiplier` (ES `identity_lookup_expanded`). If the `ai_api_key_patterns` lookup definition is missing, Splunk reports `The lookup table 'ai_api_key_patterns' is invalid` and the rule cannot run. Deploy the common package first.

### How it works

- `tstats` on `Endpoint.Processes` uses `…_process_prefilter`, a case-insensitive wildcard list of key prefixes and AI keywords, so only candidate command lines leave the summaries. The tenant `…_filter` sits inline in the same `where` clause.
- `append` adds raw events from `…_log_sources` that pass `…_log_prefilter` (a cheap regex). `…_log_identity` attributes them:
  - `user` = `coalesce(user, actor, src_user, user_name, sender, author_email, committer_email, SourceMetadata.Data.Git|Github|Gitlab.email)`. The last ones are the commit author in TruffleHog JSON output;
  - the system object = `coalesce(src_nt_host, src_host, src, SourceMetadata.Data.Git|Github|Gitlab.repository, repository, repo)`. For secret-scanner output with no endpoint, the repository URL becomes the system risk object. The host is never `dest` or `host`: on DLP data, `dest` is the website or "Disk drives" target, and `host` is the DLP management or collector server.
  - The search and its log drilldown use the same two macros, so the analyst sees exactly the events the rule scanned.
- Identity cleanup runs before risk is assigned:
  - `unknown`, `-`, `n/a`, `null`, empty values, `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE` and machine accounts (`HOST$`) are dropped as user objects. The host still receives the risk.
  - Rows with neither a user nor a host are discarded.
- Each candidate line is tested against every enabled pattern in `ai_api_key_patterns` plus the package patterns in `…_extra_patterns`. Patterns are wrapped in one of two ways:
  - **Prefix patterns** (`sk-proj-`, `hf_`, `gsk_`, …): `(?:(?<![A-Za-z0-9_-])|(?<=%3D|%3A|%20|%22|%27|%2C|\n|\r|\t))(?:<pattern>)[A-Za-z0-9_-]*`. The match may not start right after a letter, digit, `_` or `-`, so a prefix inside a longer random, base64url or JWT token does not fire. It may start after a URL-encoded `=`, `:`, space, quote or comma, or after a literal `\n`, `\r` or `\t` escape. The trailing `[A-Za-z0-9_-]*` extends the match to the end of the key, so a key longer than the library's length (for example an 80-character xAI key) is still matched and hashed whole.
  - **Contextual (label-led) patterns**, listed in `…_contextual_patterns` (AK-005/006/010/012/022, AKX-002/003/004/006): `(?<![A-Za-z0-9])(?:<pattern>)(?![A-Za-z0-9_-])`. They match at their exact length only: a 48-character value after `x-api-key:` no longer counts as a 32- or 40-character key.
  - `…_pattern_policy` then removes non-AI patterns and patterns without the context they need;
  - the key itself is the last `[A-Za-z0-9_-]+` run of the match. For contextual patterns this strips the `API_KEY=` or `x-api-key:` label, so the same key matched by two patterns hashes to one value;
  - placeholder keys (`xxxxxx`, `00000000`, `your`, `example`, `placeholder`, `dummy`, `redacted`, `changeme`, `sample`, `fake`) are dropped.
- Results are rolled up per key, then per event, then per user and host:
  - `exposure_count`: command-line executions or log events;
  - `distinct_keys`: distinct SHA-256 values of the key;
  - `provider` and `matched_patterns`;
  - `key_hints`: `<provider> ****<last4>`, one per key (at most 5). When two patterns match the same key, the providers are joined, for example `Azure OpenAI/Mistral ****9f02`;
  - `evidence_sources`, `process_names` and `log_sourcetypes`;
  - `user_dd` / `dest_dd`: drilldown-safe copies of the objects (backslash and quote replaced by `*`, so `DOMAIN\user` still matches; a missing object becomes a value that matches nothing instead of an empty token).
- Scoring:
  - Static fallback in `_risk`: user 50, system 30.
  - Dynamic `risk_score` = 50 when a key from a critical provider (OpenAI, Anthropic, Gemini) is involved, otherwise 40, multiplied by `risk_multiplier` (identity bunit sensitivity × 1.25 for privileged identities) and capped at 80. `risk_score` overrides both objects in the row.
- The rule runs every 15 minutes over `-20m@m` to `-5m@m`. Suppression is 24 h per `user,dest`, so a script that leaks the same key on every run scores once a day, not 96 times.

### Tuning macros

| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_api_key_exposure_in_code_dlp_filter` | `()` | Inline exclusions in the `Endpoint.Processes` tstats `where` clause (datamodel field names, e.g. `NOT Processes.dest IN ("ci-runner-*")`). |
| `hdsi_ai_api_key_exposure_in_code_dlp_process_prefilter` | `Processes.process IN ("*sk-proj-*", "*sk-svcacct-*", "*sk-ant-*", "*AIzaSy*", "*hf_*", "*fw_*", "*gsk_*", "*api_key*", "*api-key*", "*apikey*", "*deepseek*", …)` | Narrows candidate command lines cheaply. Exact matching happens later. Label-led patterns (`TOGETHER_API_KEY`, `CO_API_KEY`, `AZURE_OPENAI_API_KEY`) pass through `*api_key*`. If you enable a pattern with a new literal prefix, add the prefix here, or that pattern can never match a command line. |
| `hdsi_ai_api_key_exposure_in_code_dlp_log_sources` | `(index=* sourcetype IN ("*github*","*gitlab*","*bitbucket*","*dlp*","*code_review*","*secret_scan*","*gitguardian*","*trufflehog*") NOT sourcetype="stash")` | Raw logs to scan. Pin the real indexes per tenant. Never add `stash`: it is the summary, risk and notable sourcetype, not Bitbucket. To switch the log path off, use `(index=main sourcetype="hdsi_ai_log_path_disabled")`. |
| `hdsi_ai_api_key_exposure_in_code_dlp_log_prefilter` | `regex _raw="(?i)(sk-\|AIzaSy\|hf_\|…\|api[_-]?key\|apikey\|azure\|cohere\|mistral\|deepseek\|together\|fireworks)"` | Raw-text candidate filter for the log path, shared with the log drilldown. |
| `hdsi_ai_api_key_exposure_in_code_dlp_log_identity` | `eval user=coalesce(…), dest=coalesce(…)` | Log-path attribution (see How it works), shared with the log drilldown. Add your scanner's author or host field here. |
| `hdsi_ai_api_key_exposure_in_code_dlp_extra_patterns` | `split("AKX-002#~#DeepSeek#~#high#~#sk-[a-f0-9]{32}@@AKX-003…@@AKX-006…", "@@")` | Package-local key formats (eval expression; entries `id#~#provider#~#severity#~#regex`, separated by `@@`, no backslashes or double quotes). Return `null()` to disable. Remove an entry once the shared lookup covers it. |
| `hdsi_ai_api_key_exposure_in_code_dlp_contextual_patterns` | `in(pattern_id,"AK-005","AK-006","AK-010","AK-012","AK-022","AKX-002","AKX-003","AKX-004","AKX-006")` | Which patterns are label-led: exact length, and AI context required. Add any new contextual pattern you enable. |
| `hdsi_ai_api_key_exposure_in_code_dlp_pattern_policy` | drops AK-019/AK-020; contextual patterns need AI context; AK-004 needs Gemini context; AKX-002 needs `deepseek`; AKX-005 needs `fireworks` | Decides which patterns count, explained below. |
| `hdsi_ai_api_key_exposure_in_code_dlp_customizations` | `search *` | Post-normalisation hook (fields `user`, `dest`, `provider`, `matched_patterns`, `key_hints`, `distinct_keys`, `exposure_count`, …). |
| `hdsi_ai_api_key_exposure_in_code_dlp_risk_score` | `search *` | Last pipe; adjust or override `risk_score`. |

### Key coverage

"Synthetic" means a generated fake key in that format was detected by the production pipeline (see Validation). It proves the regex and the pipeline, not that the vendor still issues keys in that format. The "Format source" column says how much the format itself can be trusted.

| Provider | Pattern | Format matched | Format source | Notes |
|---|---|---|---|---|
| OpenAI | AK-001, AK-002, AK-021 | legacy `sk-…T3BlbkFJ…`, `sk-proj-…`, `sk-svcacct-…`, `sk-admin-…` | Vendor key prefixes | |
| Anthropic | AK-003, AK-017 | `sk-ant-api03-…`, `sk-ant-sid01-…` | Vendor key prefixes | AK-003 excludes session keys; AK-017 matches them. |
| Google Gemini | AK-004 | `AIzaSy` + 33 | Google API key format | Only with Gemini or Generative Language context in the same text. |
| Hugging Face | AK-007 | `hf_` + 34 or more | Vendor prefix | |
| Replicate | AK-008 | `r8_` + 36 or more | Vendor prefix | |
| Groq | AK-011 | `gsk_` + 48 or more | Vendor prefix | |
| xAI | AK-014 | `xai-` + 48 or more | Vendor prefix | Current 80-character keys match. |
| OpenRouter | AK-015 | `sk-or-v1-` + 64 hex | Vendor prefix | |
| Perplexity | AK-016 | `pplx-` + 48 or more | Vendor prefix | |
| DeepSeek | AK-022, AKX-002, AK-012 | `sk-` + 32 hex | Community-observed | AK-022 needs the `DEEPSEEK_API_KEY`-style label right before the key; AKX-002 accepts `deepseek` anywhere in the text (for example the API URL next to a `Bearer` header). AK-012 (`sk-` + 48 after a label) is an older format kept by the shared lookup. |
| Mistral | AK-010 | exactly 32 characters after a `mistral…` or `x-api-key` label | Length community-observed, no vendor prefix | Contextual. |
| Azure OpenAI | AK-005, AKX-006 | exactly 32 hex after `azure_openai`/`api_key`/`x-api-key`; exactly 84 characters after an `AZURE_OPENAI_API_KEY` or `api-key` label | Observed key lengths, no vendor prefix | Contextual. AKX-006 covers the current 84-character keys. |
| Together | AKX-003 (AK-009) | any value of 40 or more characters after a `TOGETHER_API_KEY`-style label (covers the 64-hex keys and `tgp_v1_` keys) | **No vendor-documented prefix.** AK-009 (`tog-` + 48) in the shared lookup is unverified | A bare Together key without its label is not detected. |
| Cohere | AK-006, AKX-004 (AK-018) | exactly 40 characters after a `cohere…`/`x-api-key` label (AK-006) or after `CO_API_KEY` (AKX-004, the SDK variable) | Real keys have no prefix. AK-018 (`co-` + 40) in the shared lookup is unverified | Contextual. A bare Cohere key is not detected. |
| Fireworks | AK-013, AKX-005 | `fw_` + 40 or more (AK-013); `fw_` + 20 or more with `fireworks` in the same text (AKX-005) | Vendor prefix; **length not confirmed** | AKX-005 catches shorter keys, for example `fw_` + 24. |

Not covered:
- **Bare keys without a vendor prefix.** Together, Cohere, Mistral and Azure OpenAI keys are random strings. Without the label (`…_API_KEY=`, `x-api-key:`, `api-key:`) in front of them they look like any other token and are not matched.
- **Contextual keys of a different length.** Contextual patterns match one exact length (32, 40 or 84). A Mistral value of 48 characters is not reported.
- **Keys shorter than a prefix pattern's minimum length.** The trailing extension handles longer keys, not shorter ones.
- **Keys glued to other text.** A key directly after a letter, digit, `_` or `-` is not matched (this is what blocks mid-token false positives). Only the URL-encoded separators and the `\n`/`\r`/`\t` escapes listed above are accepted in front of a key.
- **AWS (AK-019) and GitHub (AK-020)** are excluded on purpose. They are not AI keys, and an AWS access key ID is not a secret on its own.
- **Only the first match of each pattern in a line is hashed.** Two different keys of the same format in one command line count as one distinct key. `exposure_count` is still correct.

### Pattern policy

Some parts of the shared `ai_api_key_patterns` library need guarding in this rule:

- **AK-019 (AWS `AKIA`/`ASIA`) and AK-020 (GitHub tokens) are excluded.** Neither is an AI key.
- **Contextual patterns** (the `…_contextual_patterns` list) match `x-api-key`, `api_key` or a provider label followed by a fixed-length value, so the format alone fits any vendor's key. They count only when the same text names an AI provider: `openai`, `anthropic`, `claude`, `gemini`, `groq`, `huggingface`, `cohere`, `CO_API_KEY`, `mistral`, `deepseek`, `TOGETHER_API_KEY`-style labels, `fireworks`, or `llm` as a whole word. A plain `azure` does not count, because it appears in every Azure URL (an `x-api-key` header sent to an Azure web app is not an AI key). `llm` inside a longer word, such as `DllMain` or `InstallMode`, does not count.
- **AK-004 (`AIzaSy…`)** matches every Google API key, including public keys that browsers and desktop apps embed in their crash or feedback reporters. It counts only with Gemini or Generative Language context (`gemini`, `generativelanguage`, `aistudio`, `aiplatform`, `genai`, `GOOGLE_API_KEY`).
- **AKX-002 (`sk-` + 32 hex)** counts only when `deepseek` appears in the same text, and **AKX-005 (short `fw_` keys)** only when `fireworks` does, because the formats alone are generic.
- The context words are a plausibility check, not proof: a contextual key is labelled with the provider of the pattern that matched it. If several contextual patterns match the same key, the hint lists all of them.

### Known false positives / Limitations

- **Embedded vendor keys.** Over 7 days, one tenant had a desktop application whose crash-reporter command line carries a public Google API key on several hosts. The original logic matched it as a "Gemini key". The AK-004 context rule removes it.
- **Matches inside random tokens.** One tenant's endpoint DLP events contained substrings that matched `hf_[A-Za-z0-9]{34}` and `fw_[A-Za-z0-9]{40}` inside longer random strings. The leading boundary removes them, including runs that start after `_` or `-` inside base64url, JWT or SAS tokens.
- **Pre-filter noise costs search time but creates no risk.** The `*hf_*`, `*fw_*` and `*api_key*` wildcards are case-insensitive, so they also pass unrelated tokens that contain `HF_` and agent health checks whose arguments contain `api_keys`. In 24 h on 2026-10-09, Tenant A had about 6.0k executions of 670 distinct command lines that pass the pre-filter, and Tenant C about 5.8k executions of 58 distinct lines. The exact regexes reject all of them. Exclude such lines in `…_filter` if search time matters.
- **Keys that are no longer live still fire.** CI pipelines, test fixtures and keys that were already revoked still produce risk. Rotate the key anyway, then exclude the host or process in `…_filter`.
- **Keys outside command lines are not visible.** Environment variables, `.env` files and IDE settings never appear in `Processes.process`. Ingest secret-scanner output to cover repositories.
- **Secret-scanner attribution.** Scanner findings are attributed to the commit author's email and the repository (TruffleHog JSON fields), or to CIM user/host fields if the add-on maps them. A finding with none of these fields is dropped, because it has no risk object. If your scanner uses other field names, add them to `…_log_identity`.
- **SaaS repository audit logs contain no code.** GitHub and GitLab audit logs never contain file content. GitHub secret scanning and GitGuardian alerts name the secret type, not the key, so regex matching cannot see them. They need a separate rule keyed on the alert type.
- **The raw path uses `append`,** which is limited to 60 s and 50,000 events per run. With `index=*`, it searches every non-internal index for the listed sourcetypes, so pin indexes on large tenants.
- **The command-line drilldown shows the raw command line.** It lists every pre-filter candidate on the host, including any real key, to the analyst who opens it. Restrict the drilldown or the `Endpoint` data model to the roles that handle credential incidents.

### Validation

Live read-only tests on 2026-10-09 against 4 production ES tenants. The scheduled-window run uses `-4h@m` to `-5m@m`; the 7-day run (`-7d@d` to `-5m@m`) is from the previous revision earlier the same day and was not repeated, to limit search load on the tenants. Pre-filter counts are for `-24h@m` to `-5m@m`.

| Tenant | Endpoint.Processes | Code / DLP logs | Parses (search + 3 drilldowns) | 4 h run | 7-day run | Pre-filter 24 h (distinct lines / executions) | Notes |
|---|---|---|---|---|---|---|---|
| A | yes (large) | endpoint DLP only, no key material | OK | 200, 0 rows, ~31 s | 200, 0 rows, ~79 s | 670 / ~6.0k | The regexes reject every candidate. The 5 rows seen before the FP fixes (crash-reporter Google keys, DLP mid-token matches) stay suppressed. |
| B | yes (small) | none | OK | 200, 0 rows, ~11 s | 200, 0 rows, ~18 s | 0 / 0 | No candidate command lines. |
| C | yes (large) | none | OK | 200, 0 rows, ~24 s | 200, 0 rows, ~45 s | 58 / ~5.8k | No candidate holds a key. |
| D | yes (small) | endpoint DLP in a non-default index, no key material | OK | 200, 0 rows, ~8 s | 200, 0 rows, ~7 s | 0 / 0 | No candidate command lines. |

**Synthetic test (run on all 4 tenants, 30 rows in each).** 43 fake command lines and 2 fake log events were fed through the production pipeline (`makeresults` in place of `tstats` and of the log `search`; every macro and the shared lookup expanded):
- All 30 expected detections were found: every row in [Key coverage](#key-coverage), including Together `tgp_v1_`, 64-hex and `tog-` keys, a Fireworks `fw_` + 24 key, Cohere after `COHERE_API_KEY` and `CO_API_KEY`, 84-character and 32-hex Azure OpenAI keys, DeepSeek with the label and with only the API URL, OpenAI `sk-svcacct-`/`sk-admin-` (now through the shared AK-021), a key after URL-encoded `%3D`, a key after a literal `\t`, a line with two different keys (`distinct_keys=2`), a machine-account user (risk on the host only), a TruffleHog finding (attributed to the author email and the repository) and a DLP event.
- All 15 expected suppressions held: placeholder key, AWS key ID, `x-api-key` without AI context, crash-reporter Google key, `hf_`/`fw_` after a letter or digit, `_hf_` and `-co-` inside base64url tokens, `sk-` + 32 hex without DeepSeek context, a 48-character `x-api-key` sent to an Azure web app, a 64-hex `x-api-key` sent to an Azure API gateway, `--api_key` after `DllMain`, a 48-character value after `MISTRAL_API_KEY`, `fw_` without Fireworks context, and a row whose user and host are both `unknown`.
- All 28 endpoint detections passed `…_process_prefilter` (run with `| search`, the same wildcard list as the `tstats where`). This checks the wildcard list, not `tstats` itself. No real key-bearing command line exists in any tenant's data, so the `tstats` stage has only been exercised on benign candidates.

### Deployment

The package ships with `enable_alerting: false`. Before enabling it:
- deploy `hdsi_ai_rba_common` so the `ai_api_key_patterns` lookup exists;
- confirm that `Endpoint.Processes` carries full command lines on the target tenant;
- pin `…_log_sources` to the real indexes, or set it to `(index=main sourcetype="hdsi_ai_log_path_disabled")` if no code or DLP logs exist (tested in all 4 tenants: returns nothing in 1–6 s, no warnings);
- run the search over 7 days and review every row with the drilldowns;
- exclude known CI or build hosts in `…_filter`.

The rule is risk-only. A hit means a credential to rotate, so route confirmed findings to the key owner. Enabling this rule, and disabling any rule it replaces, must be one separately approved change.
