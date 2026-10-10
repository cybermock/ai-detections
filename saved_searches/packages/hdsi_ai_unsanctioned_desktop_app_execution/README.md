## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule detects endpoints running an AI desktop application that has not been sanctioned: desktop chat clients (ChatGPT, Claude, Perplexity, Pieces OS, Msty, AnythingLLM), AI-native IDEs (Cursor, Windsurf, Trae, Kiro) and agentic tools that act on the user's behalf (ChatGPT Atlas, Perplexity Comet, and the Claude Agent SDK bundled inside a third-party application). Desktop clients send prompts, pasted data, files and whole code repositories straight to the provider, outside the browser, so web/CASB controls that only inspect browser traffic do not see them, and agentic tools can read and act with the user's sessions. The rule writes risk on the user (when the process has an attributable human account) and on the system. It does not create a notable.

MITRE ATT&CK: T1588.007 (Obtain Capabilities: Artificial Intelligence).

### Prerequisites

- **`Endpoint.Processes`, accelerated.** The rule uses `summariesonly=t`, so an unaccelerated model returns nothing. Fields used are `process_name`, `process_path`, `process`, `parent_process_name`, `user` and `dest`.
  - `process_name` and `dest` are required.
  - `process_path` is required to accept the short or generic names `claude`/`claude.exe`, `trae`, `kiro` and `comet` (including `Comet Helper`). Without it those tools are not detected. Inventory-style sources such as `WinHostMon`, which carry no path, are dropped for these names.
  - `user` is optional. When it is missing, `unknown`, `SYSTEM`, `root`, `daemon`, `nobody`, a macOS `_service` account, `LOCAL SERVICE`/`NETWORK SERVICE`, `NT AUTHORITY\*` or a machine account (`HOST$`), the rule emits system risk only.
  - `original_file_name` is not used. It was absent or `unknown` in all four validation tenants.
- **Coverage must include workstations.** These are user applications. A tenant that forwards full process telemetry from servers only is blind to most of this activity. EDR alert or event-stream feeds mapped to `Endpoint.Processes` (for example CrowdStrike Event Streams) carry only the processes attached to an EDR event, so they give sparse, incidental workstation coverage (see Validation).
- **ES `identity_lookup_expanded`** (`bunit`, `category`, `priority`). `bunit` is the group key for `ai_sanctioned_entities` group entries and, through `ai_risk_multiplier`, the sensitivity key. ES identities carry no `department` field.
- **Common package `hdsi_ai_rba_common`:** `ai_unsanctioned_filter(3)` (lookup `ai_sanctioned_entities`) and `ai_risk_multiplier` (lookup `ai_department_sensitivity`). The app catalogue is package-local (the macros below), not `ai_tool_processes`.

### How it works

- `tstats` on `Endpoint.Processes` selects the candidate executable names in `hdsi_ai_unsanctioned_desktop_app_execution_process_names` (case-insensitive). Every Electron/Chromium app in the list also has its `<app> helper*` name (`Comet Helper`, `Cursor Helper (Renderer)`, `Msty Helper` ...), because an EDR source may record only a helper process. In Tenant B a Perplexity Comet session appeared only as `Comet Helper` and groups by `user`, `dest`, `process_name` and `process_path`. Grouping by path means each install location is judged on its own, so a host that runs both the Claude desktop app and an IDE-hosted agent keeps the first and drops the second. `fillnull_value="unknown"` keeps rows whose `user` or path is null.
- `hdsi_ai_unsanctioned_desktop_app_execution_signature` maps each row to `tool`, `provider` and `app_class` (`chat_client`, `ai_ide` or `agentic`). Rows it cannot map are dropped:
  - `claude.exe`/`claude` counts as the **Claude desktop** app (path under `AnthropicClaude`, `Claude.app` or a `WindowsApps` Claude package) or as the **Claude Agent SDK** (path containing `claude-agent-sdk`). The Agent SDK binary is the Claude Code executable that another application bundles and drives in SDK mode. A stand-alone Claude Code CLI install (`~/.local/bin`, `~/.claude/local`, `claude-code` paths) is not matched here; `hdsi_ai_unsanctioned_cli_execution` covers it.
  - Trae and Kiro need their install folder or `.app` bundle in the path. Comet and `Comet Helper` need `Perplexity\Comet` or `Comet.app`. Helper names map to the same tool as the main executable.
- `hdsi_ai_unsanctioned_desktop_app_execution_ide_host_exclusion` drops runtimes hosted by the IDE's GitHub Copilot integration, judged on the **process path only**: a binary under `agent-host\sdk-cache\`, under a `.vscode` `extensions\github.copilot*` folder, or the `copilot-language-server` binary. Command lines are not tested, so a Cursor, Windsurf or Claude process whose arguments or workspace path happen to contain these strings is still reported. VS Code's Copilot agent host caches the Claude Agent SDK there and runs it for Copilot sessions. That is Copilot use, not an unsanctioned Anthropic app, and an Anthropic allowlist entry would not describe the real sanction. `hdsi_ai_unsanctioned_cli_execution` excludes the same runtimes.
- Service and machine accounts become an empty `user`, so no `unknown` user accumulates risk. Rows without a `dest` are dropped.
- The user's identity `bunit` is looked up, then `ai_unsanctioned_filter(user,src,provider)` removes rows whose user, host or `bunit` group is approved in `ai_sanctioned_entities` for that provider (or `*`).
- Results are rolled up to one row per `user` + `src`, listing every tool, provider, process name and up to five paths and command lines.
- **Scoring:** `risk_score = min(50, round(base x risk_multiplier))`, with base 25 for `agentic` tools and 20 for chat clients and AI IDEs. `risk_multiplier` comes from `ai_risk_multiplier` (1.0 to 2.0). ES applies the SPL `risk_score` to both risk objects, so the user and the system receive the same score. The literal `_risk` scores (user 20, system 20) are only the fallback if the field is removed.
- Suppression is 24 hours on `user,src`. An app left open all day therefore yields at most one risk event per user and host per day. The rule runs hourly (`23 * * * *`, `-65m@m` to `-5m@m`).

### Tuning macros

| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_unsanctioned_desktop_app_execution_filter` | `()` | Exclusions inside the `tstats` where clause (`Processes.*` names), e.g. `NOT Processes.dest IN ("vdi-gold-*")` for an image-build host. |
| `hdsi_ai_unsanctioned_desktop_app_execution_process_names` | 38 quoted names | Pre-filter list used in `Processes.process_name IN (...)`. Add a new app's executable here **and** a branch in the signature macro. Keep the drilldown's inline list in step. |
| `hdsi_ai_unsanctioned_desktop_app_execution_signature` | `eval tool=case(...), provider=case(...), app_class=case(...)` | App catalogue and path corroboration. |
| `hdsi_ai_unsanctioned_desktop_app_execution_ide_host_exclusion` | `match(path_lc, "agent-host[\\\\/]sdk-cache[\\\\/]\|[\\\\/]extensions[\\\\/]github\\.copilot\|[\\\\/]copilot-language-server")` | Drops IDE-hosted Copilot runtimes by path. Set it to `false()` to report them (they score as `agentic`, provider Anthropic). |
| `hdsi_ai_unsanctioned_desktop_app_execution_customizations` | `search *` | Post-aggregation filtering on `user`, `bunit`, `src`, `tools`, `providers`, `app_class`, `process_path`. |
| `hdsi_ai_unsanctioned_desktop_app_execution_risk_score` | `search *` | Last pipe. Override `risk_score`, e.g. `eval risk_score=if(app_class="agentic",40,risk_score)` where agentic browsers are prohibited. |

Sanctioned tools belong in `ai_sanctioned_entities`, not in the filter macro. Keys are `<user>|<provider>`, `<host>|<provider>` or `<bunit>|<provider>` in lower case, with `*` for any provider; entries expire. The provider strings this rule emits are `OpenAI`, `Anthropic`, `Cursor`, `Windsurf`, `ByteDance`, `Amazon`, `Perplexity`, `Pieces`, `Msty` and `AnythingLLM`. For example, `engineering|cursor` sanctions Cursor for every identity whose ES `bunit` is `engineering`. Identities with no `bunit` can be allowlisted only by user or host.

### Threshold

None. Any execution of a catalogued AI desktop app by a non-sanctioned user or host is reportable. Per-day volume is bounded by the 24-hour suppression on `user,src`.

### Known false positives / Limitations

- **IDE-hosted Copilot (excluded by default).** In validation, the only Windows AI desktop-class process in 30 days across all four tenants was VS Code's Copilot agent host running the Claude Agent SDK binary in SDK mode (`--output-format stream-json`, plus its embedded ripgrep file listing) on one build server in Tenant C. v1.1 at first reported it as an unsanctioned Anthropic agent with score 25. In a Copilot-licensed organisation that would put risk on every developer who uses Claude through Copilot, so it is now excluded. Set `_ide_host_exclusion` to `false()` if your policy treats it as unsanctioned.
- **Removed in 1.1: generic names.** Earlier versions matched bare `zed`, `warp`, `continue`, `jan`, `pieces` and `tabnine`. `zed` is also the Linux ZFS Event Daemon, `continue` and Tabnine are IDE plug-ins rather than desktop apps, and Zed and Warp are general-purpose editor/terminal tools whose AI features are optional. LM Studio and Jan are covered by `hdsi_ai_local_llm_framework_execution` and were removed here to avoid scoring the same process twice.
- **Fixed in 1.1: Claude on Windows was never detected.** The pre-1.1 rule relied on `ai_tool_processes`, which classifies `claude.exe` as a CLI, and only accepted it under `Claude.app`, so the Windows Claude desktop app was silently discarded.
- **Fixed in 1.1: Electron helper processes.** Earlier builds listed `* Helper` names for ChatGPT, Claude and the AI IDEs but not for Comet, Perplexity, Msty or AnythingLLM. Tenant B's only AI desktop execution in 30 days, a Perplexity Comet session on a macOS workstation, was recorded only as `Comet Helper` and was missed. It is now reported (agentic, score 25).
- **Fixed in 1.1: group allowlisting.** Earlier builds ran `ai_unsanctioned_filter` before any identity lookup, so `<group>|<provider>` entries never matched. The rule now looks up `bunit` first. In all four tenants a sample identity produced a non-empty group key.
- **Expected true positives that are sanctioned:** a licensed Cursor/Windsurf rollout, or a ChatGPT/Claude enterprise desktop deployment. Add the provider for the `bunit`, user or host to `ai_sanctioned_entities`.
- **OpenAI Codex is not catalogued here.** The Codex CLI (`codex`, `codex.exe`) is covered by `hdsi_ai_unsanctioned_cli_execution`, which also excludes the IDE-hosted copy. In Tenant C, VS Code's Copilot agent host ran a `codex.exe` from `Code\agent-host\sdk-cache\codex\...` (2 events, one host, 30 days); that path is also removed by this rule's `_ide_host_exclusion`. The Codex desktop app shares the executable name `codex` with the CLI, so adding it here would score the same process in both rules. Add it only with path corroboration (for example `codex\.app[\\/]`) and in step with the CLI package.
- **Pieces OS has no helper entry.** Pieces is not an Electron app, so it has no `* Helper` processes; `pieces os`, `piecesos` and `pieces_os*` are matched.
- **Not covered by default:** Microsoft 365 Copilot (`M365Copilot.exe`), Windows Copilot and GitHub Copilot (`copilot-language-server.exe`). They are first-party, usually sanctioned tools and were seen on several hosts in Tenant C. Add them through the catalogue macros if your policy treats them as unsanctioned.
- **Same score on user and system.** The SPL `risk_score` overrides both literal `_risk` scores. If you want the host scored lower, remove `risk_score` in the `_risk_score` macro and the static 20/20 apply, or adjust the literal values.
- **Blind spots:**
  - Renamed or portable binaries outside the expected paths (for the path-corroborated tools).
  - Web use of the same providers. Pair this rule with `hdsi_ai_unsanctioned_web_access` and `hdsi_ai_dns_queries_to_ai_domains`.
  - Endpoints with sparse process telemetry. In Tenant B, DNS showed Anthropic's download host queried by about 130 sources and Cursor's backend by about 35 sources in 24 hours. Full process telemetry (Windows event logs) comes from two servers only, and workstation processes arrive only through CrowdStrike Event Streams: about 480 events from about 400 hosts in 7 days, of which 28 had macOS or POSIX paths. Those events carry only processes attached to an EDR event, so most desktop AI use there is invisible to this rule.
  - macOS and Linux: macOS is validated live by the Tenant B Comet Helper event (`/Applications/Comet.app/...`). The other macOS branches and all Linux branches are tested with synthetic rows only.

### Validation

Read-only live tests, 2026-10-09, against 4 production ES tenants. "Before" is the pre-1.1 rule, "After" is this version. Scheduled-window runs use the last 4 hours. The 30-day "After" column comes from a 30-day `tstats` inventory of every candidate name family run through the signature and exclusion macros; the one Tenant B hit was then confirmed with the full rule over 3 days.

| Tenant | Endpoint.Processes | Parses (search + 2 drilldowns) | Before (4h / 30d) | After (4h / 30d) | Notes |
|---|---|---|---|---|---|
| A | ~174M/day, Windows 4688 with path and command line, ~270 workstations running browsers | OK | 0 / 0 | 0 / 0 | No AI desktop executables by name or install path in 30 days (one installer temp file named `TRAE*.tmp` matched the name wildcard and is correctly not mapped to a tool). DNS shows ChatGPT static content, Perplexity and the Claude download host from a handful of sources. |
| B | ~51k/day: Windows event logs from two servers, plus CrowdStrike Event Streams (~480 events from ~400 hosts in 7 days, including macOS workstations) | OK | 0 / 0 | 0 / 1 | The one hit is a Perplexity Comet session on a macOS workstation, recorded only as `Comet Helper` under `/Applications/Comet.app/` with parent `Comet`, by a named user (agentic, score 25, multiplier 1.00). Missed before the helper fix. DNS shows much broader Claude, ChatGPT and Cursor desktop traffic than process data can see. |
| C | ~156M/day, about half `WinHostMon` inventory (no path) | OK | 0 / 0 | 0 / 0 | The only `claude.exe` (16 events) and `codex.exe` (2 events) in 30 days run from VS Code's Copilot `agent-host\sdk-cache` on one host; both are removed by the path-only `_ide_host_exclusion`. M365 Copilot seen on 5 hosts, not reported by design. |
| D | ~210k/day | OK | 0 / 0 | 0 / 0 | No matching activity. |

Positive-path test: 11 synthetic process rows run through the full rendered pipeline (real `identity_lookup_expanded`, `ai_sanctioned_entities` and `ai_risk_multiplier`) on all four tenants returned exactly the expected 6 rows.
- Kept: the Claude Agent SDK bundled in a third-party application (agentic, 25); Claude desktop under `AnthropicClaude` on a host that also ran the Copilot agent host (only the desktop path kept, chat_client, 20); Cursor (ai_ide, 20); Windsurf as a machine account, Pieces OS as `root` and Msty as a macOS `_service` account (system risk only).
- Dropped: the Claude Agent SDK under `Code\agent-host\sdk-cache`, the Claude Code CLI under `.local\bin`, `comet.exe` outside a Perplexity folder and `trae.exe` with no path.

`tstats` matching of `Processes.process_name` was confirmed case-insensitive (`CHROME.EXE` matched `chrome.exe`) on Tenants A and C.

### Deployment

The package ships with `enable_alerting: false`. Before you enable it, confirm that `Endpoint.Processes` covers workstations, not only servers, and that `process_path` is populated. Then run the search over 7 days and add sanctioned AI tools, users, hosts and `bunit` groups to `ai_sanctioned_entities`. This rule is risk-only. Enable it as one separately approved change.
