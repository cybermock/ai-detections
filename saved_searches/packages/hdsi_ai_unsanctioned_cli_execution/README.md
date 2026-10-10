## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule detects endpoints running an AI coding or chat CLI: Claude Code, OpenAI Codex CLI, Gemini CLI, GitHub Copilot CLI, Amazon Q / Kiro CLI, Cursor CLI, Qwen Code, OpenCode, Amp, Aider, Shell GPT, tgpt, aichat, Charm mods, Fabric, Cline, the `llm` CLI and the `openai` CLI. These tools send source code, files and terminal context to an external model provider. Agentic CLIs such as Claude Code, Codex and Gemini CLI can also run shell commands and edit files as the logged-in user. An unsanctioned one is both a shadow-AI data-handling finding and a possible execution channel. The rule creates risk on the `user` (30) and on the `src` system (20). It does not create a notable event.

### Prerequisites

- **`Endpoint.Processes`, accelerated**, with `process_name`, `parent_process_name`, `process` (full command line), `process_path`, `user` and `dest`. What breaks without each field:
  - No `parent_process_name`: the generic-name tools (`claude`, `fabric`, `llm`, `mods`, `cline`, `copilot`, `amp`) are found only through the Claude Code install-path patterns. Distinctive names still match.
  - No `process`: every node- or python-hosted CLI is missed. That covers all npm installs on macOS and Linux and the pip entry points (aider, sgpt, llm, openai).
  - No `process_path`: the native Claude Code installer on macOS (and on Linux EDRs that name a process after its image) is missed, because the process name is a version string such as `2.1.289`.
  - The child-process drilldown also uses `parent_process` and `parent_process_path`.
- Common package `hdsi_ai_rba_common` provides:
  - the `ai_unsanctioned_filter(3)` macro and the `ai_sanctioned_entities` allowlist
  - the `ai_tool_processes` lookup, which provides provider names and per-tool `enabled` switches. The rule reads it directly, keyed on the classified tool (see How it works), so one row covers every launch form of that tool.
- ES `identity_lookup_expanded` is not read by this rule. The common `ai_unsanctioned_filter` reads it to find the user's `bunit`, which is what makes group allowlist entries work. Without identity data, only user, system and organisation-wide allowlist entries apply.

### How it works

- **Prefilter (tstats, `_match` macro).** A process matches in one of four ways:
  1. Its `process_name` is a distinctive AI CLI name (`_cli_names`), with any parent.
  2. Its `process_name` is a generic name (`_generic_names`), and either the parent is an exact interactive shell or terminal (`_shell_parents`) or its command line or image path is a Claude Code install path (`_generic_path_patterns`).
  3. It is a node/bun/deno/python/uv/pipx launcher (`_launchers`) whose command line contains an AI CLI (`_cmdline_patterns`). The CLI shows up in one of two forms:
     - a package path, such as `node_modules\@google\gemini-cli\…` from a Windows npm shim, or from pnpm, Volta and npx
     - a bin symlink, such as `node --no-warnings=DEP0040 /opt/homebrew/bin/gemini` or `python3 ~/.local/bin/aider`. npm, Homebrew, nvm and bun installs on macOS and Linux run through the script's shebang, so the command line names the symlink, not the package.
  4. Its image path is the native Claude Code install (`_native_path_patterns`, `~/.local/share/claude/versions/<version>`), whatever its process name.

  Results are grouped by user, host, process name, parent and command line, and the image paths are carried along.
- **Drop non-use.** For launcher processes only (node, bun, deno, python, py, uv, uvx, pipx), the rule drops package-manager commands: `npm`/`pnpm`/`yarn`/`bun`/`pip`/`pipx`/`uv` install, update, list and similar subcommands, and `python -m pip|venv|pytest`. Installing a CLI is not running it. The package manager must be the launcher itself (`uv tool install`) or the script it runs (`node …/npm-cli.js install`), that is, the first or second command-line token. A process named after an AI CLI (`claude`, `codex`, `gemini`, …) is never dropped by this test, so `claude "npm install fails, fix it"` or `codex "pip show requests"` is detected. The same is true of a launcher run whose prompt mentions `npm install` or `python -m pytest`.
- **Drop IDE-hosted Copilot** (`_ide_host_exclusion`). VS Code's Copilot agent mode starts a bundled `codex.exe app-server` from `Code\agent-host\sdk-cache` that talks to the Copilot proxy, and editors run `copilot-language-server`. Both are IDE assistants, not CLI use, and both are excluded.
- **Classify.** A tool key (the CLI's base binary name, such as `claude`, `gemini`, `copilot`, `cursor-agent`) comes from the first of these that applies:
  - the exact process name, without `.exe`
  - the native Claude Code image path. A command-line hit counts only if the command line starts with that path, so `ls ~/.local/share/claude/versions` is not a detection.
  - for launchers only, an anchored form within the first four command-line tokens:
    - a scoped npm package directory: `@anthropic-ai/claude-code`, `@google/gemini-cli`, `@openai/codex`, `@github/copilot`, `@qwen-code/qwen-code`, `@sourcegraph/amp`, followed by a path separator, quote, space or end (so sibling packages such as `@google/gemini-cli-core` do not count)
    - a bin entry named exactly, such as `/bin/gemini` followed by a quote, space or end (so `/bin/ampx` is not Amp)
    - the Cursor CLI install directory (`cursor-agent/versions/`)
    - `python -m aider|sgpt|llm|openai`
    - `aider-chat` or `shell-gpt` as a whole token (`uvx --from aider-chat aider`) or as a pipx/uv tool venv

    A project folder such as `C:\src\claude-code-demo\server.js` or `~/aider-chat-logs/parse.py` therefore does not classify.

  Rows with no tool key are dropped. The key is looked up in `ai_tool_processes`: rows the lookup disables (`enabled=0`) or classifies as non-CLI are dropped, and `provider` comes from the lookup (a built-in fallback applies if the row is missing). The display name `ai_tool` comes from the key. The rule also sets `launch_context`:
  - `terminal`: launched from a shell
  - `ide_extension`: an extension bundle such as `.vscode\extensions\openai.chatgpt-*\...\codex.exe`
  - `interpreter`: launched through node or python with a non-shell parent
  - `other`
- **Clean risk objects.** `user` is nulled for `unknown`, empty, `SYSTEM`, `root`, `NT AUTHORITY\*`, `LOCAL SERVICE`/`NETWORK SERVICE` and machine accounts (`*$`). In that case only the system receives risk. Rows without a usable host are dropped.
- **Allowlist.** `ai_unsanctioned_filter(user,src,provider)` removes rows with an active `ai_sanctioned_entities` entry for the user, the host (`src`), the user's identity group (the ES identity `bunit`, which the common macro looks up from `user`), or the whole organisation. See "Sanctioning a tool" below for the key format.
- **Aggregate and score.** Rows are aggregated per `user` + `src`, and each row carries static scores: user 30, system 20. With `alert.suppress.fields = user,src` and a 24-hour suppression period, a user and host pair produces at most one risk event per day. The rule runs every 15 minutes (`4-59/15`) over `-20m@m` to `-5m@m`.
- **MITRE ATT&CK.** T1588.007 (Obtain Capabilities: Artificial Intelligence) and T1059 (Command and Scripting Interpreter): agentic CLIs execute shell commands on the user's behalf.
- **Drilldowns.**
  - The risk events for the object.
  - The AI CLI process activity on the host, which uses the same `_match` macro as the rule.
  - Child processes of AI CLIs (`_parent_match`). This covers parents matched by name, by the Claude Code install or native image path, or as a node/python launcher running an AI CLI.

### Tuning macros

| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_unsanctioned_cli_execution_cli_names` | `"codex","codex.exe","gemini",…,"opencode.exe"` | Distinctive CLI binary names, matched with any parent. Add new AI CLIs here only if the name does not collide with other software. |
| `hdsi_ai_unsanctioned_cli_execution_generic_names` | `"claude","llm","fabric","mods","cline","copilot","amp"` (+ `.exe`) | Names shared with other software. Each counts only from a shell or a known install path. |
| `hdsi_ai_unsanctioned_cli_execution_shell_parents` | `"cmd.exe","powershell.exe","pwsh.exe","bash","zsh",…,"WindowsTerminal.exe"` | Exact parent names that mean "typed in a terminal". |
| `hdsi_ai_unsanctioned_cli_execution_generic_path_patterns` | `"*claude-code*","*.local*bin*claude*","*.claude*local*claude*"` | Claude Code binary paths, matched on the command line and the image path. They separate Claude Code from the Claude desktop app. |
| `hdsi_ai_unsanctioned_cli_execution_native_path_patterns` | `"*.local*share*claude*versions*"` | Image path of the native Claude Code installer (macOS/Linux), where the process name is a version string. |
| `hdsi_ai_unsanctioned_cli_execution_launchers` | `"node","node.exe","bun","deno","python*","uv","uvx","pipx",…` | Runtimes whose command line is inspected. |
| `hdsi_ai_unsanctioned_cli_execution_cmdline_patterns` | `"*claude-code*","*gemini-cli*","*@openai*codex*",…,"*/bin/gemini*","*/bin/claude*",…,"*-m aider*",…` | Package paths and POSIX bin-symlink paths. Applied only to launchers. These are a prefilter only: classification then requires an exact CLI name. |
| `hdsi_ai_unsanctioned_cli_execution_match` | four-path OR expression | The tstats prefilter, shared by the rule and the process drilldown. Edit the lists above, not this expression. |
| `hdsi_ai_unsanctioned_cli_execution_parent_match` | parent-side OR expression | Used by the child-process drilldown. |
| `hdsi_ai_unsanctioned_cli_execution_ide_host_exclusion` | `match(cmd_lc, "agent-host.sdk-cache\|vscode-proxy\|github_copilot_vscode_agent\|copilot-language-server")` | Removes IDE-hosted Copilot runtimes. Set it to `false()` to include them. |
| `hdsi_ai_unsanctioned_cli_execution_filter` | `()` | Inline tstats exclusions, e.g. `NOT Processes.dest IN ("build-*")`. |
| `hdsi_ai_unsanctioned_cli_execution_customizations` | `search *` | Post-aggregation tuning, e.g. `search NOT provider="Anthropic"`. |
| `hdsi_ai_unsanctioned_cli_execution_risk_score` | `search *` | Set a numeric `risk_score` (`min(100, …)`) to override both static scores for a row. |

#### Sanctioning a tool

Add a row to `ai_sanctioned_entities` (common package) with an expiry instead of editing the macros. `allow_key` is `<lower(entity)>|<lower(provider)>`, or `<lower(entity)>|*` for every provider. `entity_type` is `user`, `system` or `group`:

| Goal | entity_type, entity, provider | allow_key |
|---|---|---|
| One developer may use Claude Code | `user`, the `user` value exactly as this rule emits it (for example `CORP\jdoe` or `jdoe@example.com`), `Anthropic` | `corp\jdoe\|anthropic` |
| A build host may run any AI CLI | `system`, the `src` value (host name), `*` | `build01\|*` |
| The engineering team may use Gemini CLI | `group`, the ES identity `bunit` value, `Google Gemini` | `engineering\|google gemini` |
| The whole organisation is licensed for GitHub Copilot | `group`, `*`, `GitHub Copilot` | `*\|github copilot` |

The `provider` must be the string this rule emits: `Anthropic` (Claude Code), `OpenAI` (Codex CLI, `openai` CLI), `Google Gemini`, `GitHub Copilot` (the `copilot` CLI), `Microsoft Copilot` (the legacy `gh-copilot` extension), `Amazon` (`amazon-q`, `qchat`), `Kiro` (`kiro-cli`), `Cursor`, `Alibaba Qwen`, `OpenCode`, `Sourcegraph` (Amp), `Aider`, `Shell GPT`, `LLM CLI`, `Charm` (mods), `Fabric`, `Cline`, `tgpt`, `aichat`. To approve Copilot CLI in both its forms, add one key for `github copilot` and one for `microsoft copilot`. A group key only works for users whose `user` value (or the bare name without `DOMAIN\` or `@suffix`) resolves in `identity_lookup_expanded` with a non-empty `bunit`; see Limitations.

To stop detecting a tool everywhere, set `enabled=0` on its base-name row in `ai_tool_processes` (for example `claude`, `gemini`, `copilot`, `cursor-agent`, `qwen`, `amp`; not the `.exe` row). The rule looks up the classified tool key, so this one change also disables the node- or python-hosted runs and the native Claude Code version-string image. Every tool this rule classifies has a row in the lookup.

### Known false positives / Limitations

- **Live validation covered Windows endpoints only.** All Endpoint.Processes data in the four validation tenants comes from Windows: Security 4688 events, `WinHostMon` and a small EDR share. None of them had macOS or Linux endpoints. The macOS and Linux forms of the CLIs are covered by the synthetic control (see Validation), not by live detections:
  - npm and Homebrew bin symlinks run as `node`
  - the native Claude Code version-string image
  - pip entry points run as `python3`

  Before you rely on those paths, confirm in the target tenant that its macOS/Linux EDR maps the full command line into `process` and the image path into `process_path`.
- **Generic names are gated on purpose.** In one tenant, Microsoft Service Fabric's `Fabric.exe` (parent `FabricHost.exe`, machine accounts) ran about 8.7k times a day on 3 servers. The pre-v1.1 parent regex (`sh|wt|…`, unanchored) would also match parents such as `dashost.exe` or `ssh`. The v1.1 rule uses exact shell names, so Service Fabric produces no rows.
- **VS Code Copilot agent mode looks like Codex.** In one tenant, the only `codex.exe` activity in 7 days was VS Code's Copilot agent host. Its command line routes to `vscode-proxy` with `AI_AGENT=github_copilot_vscode_agent`. It is excluded by default. If your tenant treats Copilot agent mode as unsanctioned, set `_ide_host_exclusion` to `false()`. The OpenAI Codex IDE extension (`openai.chatgpt`) is still detected, as `ide_extension`.
- **Missing parent.** Windows 4688 events and `WinHostMon` inventory snapshots often carry no parent process. In one tenant about half of the AI-related process rows had `parent_process_name=unknown`. A generic-name CLI with no parent is detected only through the Claude Code path patterns. On macOS/Linux, launching through `node` or `python` does not depend on the parent.
- **Classification looks at the first four command-line tokens.** If a launcher's prompt argument falls within those four tokens and names another CLI's package path or `/bin/<cli>`, the row can be labelled as the wrong tool. It is still detected. Interpreters started with flags that take a separate value (for example `node --require x.js /usr/local/bin/gemini`) can push the CLI past the fourth token and be missed. A project script that is itself under a `bin` folder and named exactly like a CLI (`node ~/proj/bin/claude.js`) is still classified as that CLI.
- **Group allowlisting depends on identity coverage.** In a 1-hour sample of interactive-process users (node, python, shells, VS Code), 17% resolved to an identity `bunit` in Tenant A and 20% in Tenant C. Tenant B's endpoint users in that sample were all machine or service accounts. Unresolved users can be sanctioned only by user, system or organisation-wide keys. Improving the ES identity lookup raises this coverage.
- **Child-process drilldown and the Claude desktop app.** The desktop app's executable is also `claude.exe`. The drilldown skips parents whose image path is the desktop app (`AnthropicClaude`, `Claude.app`, `WindowsApps\…Claude…`) and Electron helper children (`--type=`). When the EDR does not record `parent_process_path`, children that the desktop app starts without `--type=` (for example MCP servers) can still appear.
- **Not covered:**
  - `goose`, which collides with the pressly/goose database migration CLI
  - bare `q` (Amazon Q's binary name, too generic; `qchat`, `amazon-q` and `kiro-cli` are covered)
  - Python library use (`import openai`)
  - CLIs renamed by the user
  - global npm prefixes outside a `bin` directory that run the CLI without the package path

  AI use through the browser or desktop apps is covered by the DNS, web and desktop-app rules.
- **Expected benign hits:** developers who are evaluating tools, and approved pilot users. Allowlist them with `ai_sanctioned_entities`.
- **Pre-v1.1 versions:**
  - emitted risk on the literal `unknown` user and host
  - scored once per process name per hour
  - missed every node- or python-hosted CLI and the native macOS Claude Code install
  - dropped real CLI runs whose prompt mentioned `npm install` or `-m pytest`
  - shipped a process drilldown with no `from datamodel` clause, which always returned 0 rows

### Validation

Read-only live tests ran on 2026-10-09 against 4 production ES tenants. All endpoint data in these tenants is Windows.

| Tenant | Endpoint.Processes (24h) | Parses (rule + 3 drilldowns) | Rule rows: 4h / 7d | Notes |
|---|---|---|---|---|
| A | ~174M (Windows 4688, small EDR share) | OK | 0 / 0 (7d runtime 45s) | The prefilter matched nothing in 7 days. Service Fabric `Fabric.exe` is gated out. |
| B | ~51k (servers, machine accounts) | OK | 0 / 0 (1s) | Server-only endpoint data. |
| C | ~156M (Windows 4688 + `WinHostMon`) | OK | 0 / 0 (19s) | The prefilter matched 2 `codex.exe` events on 1 developer host, both from the VS Code Copilot agent host, which is excluded by default. With the exclusion set to `false()`, the rule returns exactly that host as `OpenAI Codex CLI` / `ide_extension`. The child-process drilldown expression returned that host's `codex.exe` → `conhost.exe` child. |
| D | ~210k (servers) | OK | 0 / 0 (2s) | No AI CLI activity. |

The **Rule rows** column is the scheduled search over the auto window (last 4 hours), re-run after the final changes with no FATAL or ERROR messages (runtimes 8 s, 2 s, 4 s, 2 s for A–D). The 7-day figures come from the previous round, whose `_match` prefilter is unchanged.

A synthetic positive control ran on all four tenants. It applied the `_match` prefilter as a `search`, followed by the complete post-tstats pipeline with the repo lookups inlined. The results were identical in every tenant:

| Check | Rows | Result in A, B, C, D |
|---|---|---|
| Full rule | 38 | 23 expected detections, 15 expected drops, correct `ai_tool` and `provider` on every row |
| `ai_tool_processes` row `claude` set to `enabled=0` | 38 | 16 detections: all 7 Claude Code rows dropped (native name, Windows npm shim, node-hosted `/bin/claude`, native version-string image) |
| Group allowlist: a real identity from the tenant's `identity_lookup_expanded`, with a `<bunit>\|google gemini` key injected | 2 | Gemini CLI row dropped through the identity `bunit`; the same user's Claude Code row kept |
| Child-process drilldown gate (`_parent_match`) | 6 | 3 CLI children kept; desktop-app renderer, Electron GPU child and `Claude.app` child dropped |

- **Detected, macOS/Linux:**
  - Gemini CLI as `node --no-warnings=DEP0040 /opt/homebrew/bin/gemini`
  - native Claude Code with the process name `2.1.289` and image `~/.local/share/claude/versions/2.1.289`, from a shell and from an IDE parent
  - Qwen Code, Copilot CLI (nvm) and Amp as `node …/bin/<cli>`
  - Claude Code as `node /usr/local/bin/claude -p "… python -m pytest"`
  - Aider as `python3 ~/.local/bin/aider --message "npm install …"`, as `uvx --from aider-chat aider` and as `python3 -m aider` run by root (system-only risk)
  - Shell GPT from its pipx venv, the `llm` and `openai` pip entry points, Cursor CLI's bundled node, `kiro-cli` (provider `Kiro`)
  - native CLIs whose prompt starts with a package-manager command: `claude "npm install fails …"`, `gemini "yarn add react …"`, `codex "uv add httpx …"`, `codex "pip show requests …"`
- **Detected, Windows:**
  - native `claude.exe`, including `"…\.local\bin\claude.exe" "pip install requests fails, why"`
  - the npm Claude Code shim (quoted paths with spaces)
  - the npm Copilot CLI (provider `GitHub Copilot`)
- **Dropped:**
  - `npm install -g` on macOS and on Windows (quoted `Program Files` path)
  - `pip install`, `uv tool install`
  - `/bin/ampx` (prefix only)
  - project folders `claude-code-demo`, `aider-chat-logs`, `gemini-cli-plugin`, `cursor-agent-rules`, and the `@google/gemini-cli-core` sibling package
  - Copilot language server
  - the Claude desktop app
  - `ls` of the native Claude directory
  - VS Code Copilot agent host
  - Service Fabric

Expected volume at the scheduled cadence is 0 risk events per day in all four tenants today. AI use in these tenants is browser and SaaS based. Where developers adopt AI CLIs, expect at most one event per user and host per day.

### Deployment

The package ships with `enable_alerting: false`. Before enablement:

1. Confirm that the target tenant's `Endpoint.Processes` summaries carry `process`, `process_path` and `parent_process_name`, including from macOS and Linux EDR sources if there are any.
2. Run the search over 7 days to list current AI CLI users and hosts.
3. Add sanctioned users, hosts, groups or organisation-wide licences to `ai_sanctioned_entities` using the key format in "Sanctioning a tool", or set `enabled=0` on the tool's base-name row in `ai_tool_processes`.
4. Confirm that the risk objects resolve to real users and hosts.

The rule is risk-only. Enabling it and adjusting any aggregator thresholds must be one separately approved change.
