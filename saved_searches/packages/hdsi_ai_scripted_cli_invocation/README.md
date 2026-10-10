## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule detects AI command-line agents that start without a person at the keyboard. Covered tools include Claude Code, OpenAI Codex, Gemini CLI, GitHub Copilot CLI, Qwen Code, Amazon Q, Aider, `llm` and `sgpt`, whether they run as their own binary, inside `node` (npm installs), inside `python` (pip, pipx and uv installs on Linux and macOS) or as a native Claude Code install. A run counts as unattended in four cases: a script interpreter, build tool or orchestrator launched it; another AI agent launched it; it ran headless (`claude -p`, `codex exec`, `gemini -p`, `aider --message`); or it ran with a flag that switches off the agent's approval prompts or sandbox (`--dangerously-skip-permissions`, `--yolo`/`-y`, `--trust-all-tools`, `-s danger-full-access`, `--ask-for-approval never`).

An unattended agent carries the user's credentials, file access and network position, and nobody reviews the commands it runs. In August 2025 the malicious Nx "s1ngularity" npm packages showed the abuse case: a `postinstall` script called the victim's own `claude`, `gemini` and `q` CLIs with exactly these bypass flags to search the disk for secrets. The rule writes risk on the user (when the process has a human account) and on the system. It does not create a notable.

MITRE ATT&CK: T1059 (Command and Scripting Interpreter).

### Prerequisites

- **`Endpoint.Processes`, accelerated.** The rule uses `summariesonly=t`, so an unaccelerated model returns nothing. It reads `process_name`, `process` (the full command line), `parent_process_name`, `parent_process` (the parent command line), `user` and `dest`.
  - `process_name` and `dest` are required.
  - `process` (the command line) drives most of the rule: the headless and bypass flags, CLIs hosted by `node`/`python`, native Claude Code installs, remote-IDE detection when the parent command line is missing, and the collision checks. Windows 4688 events only carry it when "Include command line in process creation events" is enabled. Without it, only the automation-parent path works.
  - `parent_process_name` separates "a program launched the CLI" from "a person typed it". When it is missing, only the command-line flags can trigger the rule. In validation it was filled on about 68%, 13%, 19–38% (it varied between the windows checked) and 87% of process events in Tenants A–D. Windows 4689 (process exit) events and `WinHostMon` inventory events carry no parent.
  - `parent_process` is optional but improves accuracy. It is used to:
    - recognise remote IDE extension hosts, which run as a plain `node` (`~/.vscode-server/.../node .../bootstrap-fork --type=extensionHost`);
    - tell a node script that launches an AI CLI apart from an AI CLI relaunching itself, and from one AI agent launching another;
    - recognise `npx`/`pipx` running inside an interpreter.

    For `node`/`python` processes it was filled on about 95% of events in Tenant A and 3% in Tenant C. When it is missing, a `node` parent of a Node-hosted CLI is treated as a self-relaunch (the conservative choice), and a `node` parent of a CLI that lives under an IDE extensions folder is treated as an IDE.
  - `user` is optional. When it is missing, `unknown`, `SYSTEM`/`LOCAL SERVICE`/`NETWORK SERVICE`, another `NT AUTHORITY` principal or a machine account (`HOST$`), the rule writes system risk only. Domain service accounts stay attributed unless you add them to `hdsi_ai_scripted_cli_invocation_nonhuman_users`.
- **Coverage must include developer workstations and build/CI hosts.** AI CLIs run there, mostly on macOS and Linux. A tenant that only forwards Windows server process events cannot see them.
- **ES `identity_lookup_expanded`** feeds `ai_risk_multiplier` (identity `bunit` sensitivity and the privileged/critical flag) and the group key of `ai_unsanctioned_filter`.
- **Common package `hdsi_ai_rba_common`:**
  - `ai_process_filter` (lookup `ai_tool_processes`, rows with `usage_type=cli` and `enabled=1`).
  - `ai_unsanctioned_filter(3)` (lookup `ai_sanctioned_entities`).
  - `ai_risk_multiplier` (lookup `ai_department_sensitivity`).

### How it works

- `tstats` on `Endpoint.Processes` selects five kinds of process and groups them by `user`, `dest`, `parent_process_name`, `parent_process`, `process_name` and `process` (`fillnull_value="unknown"` keeps rows with no parent or user):
  - AI CLI executable names (`hdsi_ai_scripted_cli_invocation_cli_names`).
  - `node`/`bun`/`deno` (`..._js_hosts`) whose command line is an npm-installed AI CLI (`..._node_cli_patterns`), e.g. `node.exe ...\@anthropic-ai\claude-code\cli.js`.
  - `python*`/`py.exe` (`..._py_hosts`) whose command line is a pip/pipx/uv-installed Aider, `llm` or `sgpt` (`..._python_cli_patterns`), e.g. `python3 ~/.local/bin/aider`.
  - Native Claude Code: a `process_name` that starts with a digit (`..._native_version_names`; the image is `~/.local/share/claude/versions/2.1.x`) and a command line of `claude` or `.../claude` (`..._native_cli_patterns`).
  - `q`/`qchat` processes (`..._amazon_q_names`) running `chat` (Amazon Q).
- Each process gets a canonical tool key: Node-, Python- and native-hosted CLIs become `claude`, `codex`, `gemini`, `gh-copilot`, `qwen`, `aider`, `llm` or `sgpt`; `copilot` becomes `gh-copilot`; `q`/`qchat` become `amazon-q`.
- `..._name_collision_check` drops processes that only share a name with a CLI: macOS `.app` bundles (except `Python.app`, the running image of framework Python, so pip/pipx CLIs on macOS are kept), the Windows Claude desktop app, the Claude Code copy the desktop app bundles under `Claude\claude-code\<version>\`, Store apps, and Microsoft Service Fabric's `Fabric.exe`.
- `ai_process_filter` keeps tools that are enabled with `usage_type=cli` in `ai_tool_processes`. Rows with no `dest` are dropped.
- The parent's own AI tool is worked out from its name or command line (a `node` running Claude Code, Codex, Gemini CLI, Copilot CLI or Qwen Code; a native `claude`, `codex`, `gemini`, `copilot`, `q` and similar). The parent is then classified, in this order:
  - **none:** no parent recorded.
  - **ide:** a local IDE executable (VS Code, Cursor, Windsurf, JetBrains, Zed and others, `..._ide_parents`), or a remote IDE extension host recognised by its command line (`..._ide_host_cmd`): VS Code Remote-SSH, WSL, Dev Containers and Codespaces (`.vscode-server`, `bootstrap-fork --type=extensionHost`), the Cursor and Windsurf `-server` equivalents, and JetBrains `remote-dev-server`. When the parent command line is missing, a `node` parent of a CLI installed under an IDE `extensions` folder also counts.
  - **cli_relaunch:** the same AI CLI relaunching itself (Gemini CLI always relaunches itself in a child `node`; the Codex npm shim starts the native `codex`), or a Node-hosted CLI under a `node` parent whose command line is unknown.
  - **ai_agent:** a different AI CLI launched it, e.g. Claude Code starting Gemini CLI as a sub-agent. This is scored like an automation parent.
  - **npm_launcher:** `node` starting a CLI binary under `node_modules` when the parent command line is unknown.
  - **package_runner:** `npx`, `uvx`, `uv`, `pipx`, `pnpm`, `yarn`, `npm`, `bunx`, either as the parent executable or as the command line of a `node`/`python` parent (`..._package_runners`). People type these to start a CLI.
  - **automation:** script interpreters (`python`, `node`, `ruby`, `perl`, `wscript`/`cscript`), build tools (`make`), orchestrators (`n8n`, `ansible-playbook`, `xargs`, `parallel`) and the few schedulers or CI agents that exec a binary directly (`..._automation_parents`). PowerShell and other shells are not included because people type commands in them.
  - **shell_or_other:** everything else, including shells.
- The command line is checked for headless use and for permission bypass:
  - **Headless:** `..._unattended_flags` (`--print`, `--prompt`, `--message`, `--output-format` and others), `..._unattended_subcommands` (`codex exec`/`e`, `opencode run`, `goose run`, `crush run`), and the short `-p` only for the tools in `..._short_p_tools` (Claude Code, Gemini CLI, Qwen Code, Cursor CLI, Copilot CLI, opencode). Elsewhere `-p` means something else: `codex --profile`, `llm --param`, `fabric --pattern`.
  - **Headless is never set for the one-shot chat CLIs** in `..._chat_clis` (`llm`, `sgpt`, `tgpt`, `mods`, `fabric`, `aichat`, `openai`). They answer one prompt and exit by design, so `llm "question"` or `fabric -p summarize` typed at a terminal is a person. They score only when an automation parent or another AI agent launches them.
  - **Bypass:** `..._bypass_flags`, plus `-y` for Gemini CLI and Qwen Code, and `-a never` for Codex. Codex `--full-auto` is not a bypass: it keeps the workspace-write sandbox and is the documented CI mode for `codex exec`, which is caught as headless anyway.
- A row is kept only if:
  - it has a bypass flag (any parent);
  - its parent is automation or another AI agent; or
  - it ran headless and its parent is not an IDE.

  Interactive use from a terminal or a package runner, CLI self-relaunches and IDE extensions (local or remote) that start their bundled agent are dropped. `hdsi_ai_unsanctioned_cli_execution` already covers plain interactive use.
- Non-human accounts (`..._nonhuman_users`) become an empty `user`, so no `unknown` user collects risk. Sanctioned entities are removed (see below). Rows are rolled up to one per `user` + `src`, listing the tools, parent processes, reasons and up to 5 command lines.
- **Scoring:** `risk_score = min(80, round(base x risk_multiplier))`. `risk_multiplier` (1.0 to 2.0) comes from `ai_risk_multiplier`. The SPL `risk_score` applies to both risk objects. The literal `_risk` scores (user 30, system 20) are the fallback if the field is removed. Base scores:

| Condition | Base |
|---|---|
| Automation parent or another AI agent, and a bypass flag | 50 |
| Bypass flag, any other parent (including an IDE) | 40 |
| Automation parent or another AI agent, headless | 35 |
| Automation parent or another AI agent | 30 |
| Headless run from a shell, package runner, self-relaunch or with no parent | 20 |

- Suppression is 24 hours on `user,src`. A pipeline that calls an AI CLI every few minutes therefore yields one risk event per user and host per day. The rule runs hourly (`23 * * * *`, `-65m@m` to `-5m@m`).

#### How real schedulers and CI reach the CLI

The automation-parent path only sees the direct parent. In practice most scheduled and CI runs reach the CLI through a shell, so they are caught by the headless and bypass flags, not by the parent:

- cron and systemd timers run `/bin/sh -c <command>`.
- GitHub Actions, GitLab and Azure Pipelines runners exec a `bash` or `pwsh` step script.
- On Windows 10+ and Server 2016+, scheduled tasks that start an executable show `svchost.exe` as the parent (`taskeng.exe` is Windows 7 era; `taskhostw.exe` only hosts COM-handler tasks).
- On Windows, `claude.cmd`/`codex.cmd` npm shims run through `cmd.exe`.
- AI agents usually run commands through a shell too (Claude Code's and Codex's command tools start `bash -c`), so an agent that calls another CLI through its shell tool is scored on that CLI's flags (headless 20), not as `ai_agent`. The `ai_agent` class sees direct spawns, such as a Node-hosted agent or an MCP server starting a sub-agent.

A CI job that runs an AI CLI interactively (no `-p`, no `exec`, no bypass flag) is rare because it would hang waiting for input. A Python, Node or Ruby script that calls the CLI directly is caught by its parent.

### Tuning macros

| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_scripted_cli_invocation_filter` | `()` | Exclusions inside the `tstats` where clause (`Processes.*` names), e.g. `NOT Processes.dest IN ("ci-runner-*")`. |
| `hdsi_ai_scripted_cli_invocation_cli_names` | 40 executable names | AI CLI names for `Processes.process_name IN (...)`. A name only produces risk once `ai_tool_processes` has an enabled `cli` row for it. |
| `hdsi_ai_scripted_cli_invocation_js_hosts` / `_py_hosts` / `_native_version_names` / `_amazon_q_names` | `node`, `bun`, `deno` / `python*`, `py.exe` / `0.*`–`9.*` / `q`, `qchat` | Host process names that are paired with a command-line pattern in the `tstats` where clause. They are not AI tools on their own. |
| `hdsi_ai_scripted_cli_invocation_node_cli_patterns` | `*claude-code*`, `*@openai*codex*`, `*gemini-cli*`, `*@github*copilot*`, `*@qwen-code*` + `*/bin/<cli>*` | Command lines of npm-installed CLIs running inside `node`/`bun`/`deno`. |
| `hdsi_ai_scripted_cli_invocation_python_cli_patterns` | `*/bin/aider`, `*/bin/llm`, `*/bin/sgpt`, `* -m aider`, `* -m llm` | Command lines of Python-packaged CLIs running inside `python*`. |
| `hdsi_ai_scripted_cli_invocation_native_cli_patterns` | `"claude","claude *","*/claude","*/claude *","*/claude/versions/*"` | Command lines of the native Claude Code install, whose image name is a version number. |
| `hdsi_ai_scripted_cli_invocation_automation_parents` | regex of interpreters, build tools, orchestrators, schedulers, CI agents | Parents that count as "a program launched it". Add your orchestration tools here, e.g. `airflow`. `svchost.exe` is deliberately absent because it is the parent of every Store app; package runners are deliberately absent. |
| `hdsi_ai_scripted_cli_invocation_package_runners` | regex of `npm`, `npx`, `pnpm`, `pnpx`, `yarn`, `bunx`, `uv`, `uvx`, `pipx` | Interactive launchers that are not automation. |
| `hdsi_ai_scripted_cli_invocation_ide_parents` | regex of local IDE executables | IDE launches are ignored unless a bypass flag is present. |
| `hdsi_ai_scripted_cli_invocation_ide_host_cmd` | regex of `bootstrap-fork`, `--type=extensionhost`, `.vscode-server/`, `.cursor-server/`, `.windsurf-server/` and other `-server` folders, IDE `extensions` folders, `remote-dev-server` | Remote IDE extension hosts that run as `node` or `java`. Add your own remote-development layout here. |
| `hdsi_ai_scripted_cli_invocation_unattended_flags` | `--print`, `--prompt`, `--message`, `--message-file`, `--headless`, `--non-interactive`, `--no-interactive`, `--output-format` | Long-form headless flags. |
| `hdsi_ai_scripted_cli_invocation_unattended_subcommands` | `codex exec`/`codex e`, `opencode run`, `goose run`, `crush run` | Headless subcommands, anchored to the tool name so prompt text such as `claude "run the tests"` does not match. |
| `hdsi_ai_scripted_cli_invocation_short_p_tools` | `claude`, `gemini`, `qwen`, `cursor-agent`, `gh-copilot`, `copilot`, `opencode` | Tools whose short `-p` means headless print/prompt. |
| `hdsi_ai_scripted_cli_invocation_chat_clis` | `llm`, `sgpt`, `tgpt`, `mods`, `fabric`, `aichat`, `openai` | One-shot chat CLIs that never count as headless; they score only from an automation or AI-agent parent, or with a bypass flag. |
| `hdsi_ai_scripted_cli_invocation_bypass_flags` | `--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `--yolo`, `--trust-all-tools`, `--allow-all-tools`, `--allow-all-paths`, `--yes-always`, `--approval-mode yolo`, `--permission-mode bypassPermissions`, `--sandbox`/`-s danger-full-access`, `-c sandbox_mode=danger-full-access`, `--ask-for-approval never`, `-c approval_policy=never` | Flags that switch off the agent's own approval prompts or sandbox. The short `-y` (Gemini CLI, Qwen Code) and `-a never` (Codex) are handled in the search. Add new vendor flags as they ship. |
| `hdsi_ai_scripted_cli_invocation_name_collision_check` | `where NOT match(cmd_lc, ...)` | Drops non-CLI processes that share a name. Extend it for collisions in your estate. Do not remove it: `Fabric.exe` is Microsoft Service Fabric on many Windows servers. |
| `hdsi_ai_scripted_cli_invocation_nonhuman_users` | regex of unknown, `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `NT AUTHORITY\*`, `HOST$` | Accounts that get system risk only. Add your service-account convention, e.g. `\|svc[-_.].*`. |
| `hdsi_ai_scripted_cli_invocation_customizations` | `search *` | Post-aggregation filtering on `user`, `src`, `tools`, `reasons`, `parent_processes`, `parent_class`, `process`. |
| `hdsi_ai_scripted_cli_invocation_risk_score` | `search *` | Last pipe. Override `risk_score`, e.g. `eval risk_score=if(match(reasons,"bypass"),risk_score,10)` where headless use in CI is routine. |

#### Allowlisting approved automation

Approved automation (build agents, an internal code-review bot, a team that uses `claude -p` in git hooks) belongs in `ai_sanctioned_entities` in the common package, not in the filter macro. `ai_unsanctioned_filter(user,src,provider)` runs on each process row before the roll-up. The `provider` is the `ai_tool_processes` provider of the tool: `Anthropic` (claude), `OpenAI` (codex, openai), `Google Gemini` (gemini), `Microsoft Copilot` (Copilot CLI, keyed `gh-copilot`), `Alibaba Qwen`, `Amazon` (Amazon Q), `Aider`, `LLM CLI`, `Shell GPT` and so on. `allow_key` is lowercase. Example rows:

| What to allow | `ai_sanctioned_entities` row |
|---|---|
| A CI runner using any AI CLI | `system,ci-runner-01,*,global,2027-06-30,devops,code-review pipeline,1,ci-runner-01\|*` (the entity is the `dest` value as the EDR reports it) |
| A build account using Claude Code | `user,svc_build,Anthropic,provider,2027-06-30,devops,nightly review job,1,svc_build\|anthropic` (the entity is the `user` value as the EDR reports it, e.g. `corp\svc_build` when it carries a domain) |
| A business unit using Codex | `group,engineering,OpenAI,group,2027-06-30,security,approved,1,engineering\|openai` (matched on the user's ES identity `bunit`) |
| The whole organisation using Claude Code | `group,*,Anthropic,global,2027-06-30,security,enterprise licence,1,*\|anthropic` |

Allowlist entries expire. An organisation-wide or group entry also hides the bypass-flag cases for that provider, so prefer system or user entries for CI. To keep bypass cases visible while allowlisting routine headless use, leave the provider unsanctioned and lower the headless score in `..._risk_score` instead.

### Threshold

None. Every unattended invocation is reportable. Daily volume is bounded by the 24-hour suppression on `user,src`.

### Known false positives / Limitations

- **Sanctioned automation is the expected true positive.** Examples: CI jobs that run `claude -p` or `codex exec` for code review, scheduled reports through `llm`, and developers' git hooks. Allowlist these in `ai_sanctioned_entities` after review. The bypass-flag cases deserve a look even when sanctioned.
- **A person running a headless command still scores 20.** `claude -p "write a commit message"` or `codex exec --full-auto` typed at a terminal is technically unattended (the agent runs to completion with no approval step), so it is kept at the lowest base score. Raise the bar in `..._risk_score` if your developers do this routinely.
- **IDE-hosted agents are ignored unless a bypass flag is present.** This covers local IDEs and remote extension hosts (VS Code Remote-SSH, WSL, Dev Containers, Codespaces, the Cursor and Windsurf servers, JetBrains remote development). An IDE with a remote layout that `..._ide_host_cmd` does not know shows up as `node` parent (automation, 30–35): add its folder or command line to that macro. A bypass flag from an IDE still scores 40, because the IDE does not re-add the approvals the flag removes.
- **Generic names.** `ai_tool_processes` marks `llm`, `mods`, `fabric`, `copilot`, `goose`, `crush` and `amp` with `requires_context=1` because other software uses the same names. This rule never scores a name alone: it needs an automation or AI-agent parent or a CLI-specific flag, and the collision check removes known collisions. If a colliding tool is launched by a script in your estate, extend `..._name_collision_check` with its path.
- **Name collisions found in validation:**
  - Microsoft Service Fabric `Fabric.exe` under `FabricHost.exe`: about 61k events in 7 days on 3 servers in Tenant A. The collision check drops it.
  - IDE-hosted agents: `codex.exe app-server` and `copilot-runtime.exe --headless` launched by VS Code in Tenant C. They are ignored because the parent is an IDE. `copilot-runtime.exe` is not a listed name.
- **Claude desktop app.** The desktop app starts its bundled Claude Code with `--output-format stream-json`. The collision check drops the copies under `.app/Contents/` (macOS) and `Claude\claude-code\<version>\` (Windows, inferred from the macOS layout and not yet observed in tenant data). If a tenant shows desktop-driven sessions as "headless one-shot run", extend the collision check with the observed path.
- **Missing parent or command line.** Without `parent_process_name` the automation and AI-agent paths are blind. Without `process` the flag paths, hosted CLIs, native installs and collision checks are blind. Inventory sources such as `WinHostMon` cannot drive this rule.
- **Self-relaunch versus a Node script.** When `parent_process` is not collected, a `node` script that launches a Node-hosted CLI cannot be told apart from Gemini CLI's own relaunch, or from another Node-hosted agent, so it is scored on its flags only (headless 20, bypass 40) instead of as automation.
- **Blind spots:**
  - Renamed binaries.
  - Python-hosted CLIs launched through a Windows path not listed in `..._python_cli_patterns` (the `aider.exe`/`llm.exe` launchers are covered by name).
  - Native Claude Code where the EDR reports neither `claude` in the command line nor the `versions` path.
  - CLIs inside containers or WSL whose process events are not collected.
  - Agent SDKs called directly from Python or Node without a CLI process. Pair this rule with `hdsi_ai_api_access_from_non_dev_endpoint` and the DNS/web rules for that.
- **The drilldown** lists AI CLI processes on the host and their direct children, including native Claude Code (`claude ...` and `.../claude/versions/...`) and Node-hosted CLIs. It does not list children of a version-named native Claude Code process.
- **Related rules:** `hdsi_ai_unsanctioned_cli_execution` (any AI CLI use), `hdsi_ai_agent_autonomous_action_detection` (what an agent runs once started) and `hdsi_ai_agent_framework_execution` (CrewAI, AutoGen, LangGraph and similar).

### Validation

Read-only live tests, 2026-10-09, against 4 production ES tenants. "Before" is the pre-1.1 rule, "After" is this version. The windows are the last 4 hours for the scheduled-window runs and 7 days for the wide run.

| Tenant | Endpoint.Processes | Parses (search + 2 drilldowns) | Before (4h) | After (4h / 7d) | Notes |
|---|---|---|---|---|---|
| A | ~174M/day, Windows 4688 with command line | OK | 0 rows | 0 / 0 (7d in 42s, 4h in 8s) | No AI CLI processes in 7 days except Service Fabric `Fabric.exe` (name collision, dropped). |
| B | ~51k/day, servers only | OK | 0 rows | 0 / 0 | No AI CLI processes; no workstation coverage. |
| C | ~156M/day, about half `WinHostMon` inventory | OK | 0 rows | 0 / 0 | Only IDE-hosted Codex and Copilot agents under local VS Code, correctly ignored. |
| D | ~210k/day | OK | 0 rows | 0 / 0 | No AI CLI processes. |

No tenant had any AI CLI started by a script, run headless, or run with a bypass flag in 7 days.

**What real data did and did not exercise.** All four tenants collect Windows process telemetry only. A 24-hour `tstats` for `node`, `python3`, `bash` or `zsh` processes, and a search for any `*-server*bootstrap-fork*` process, returned 0 rows in every tenant. So the Linux and macOS logic has never run against real events: native Claude Code, Python-hosted CLIs, the `node .../bin/<cli>` patterns, the POSIX self-relaunch and package-runner handling, remote IDE hosts and the macOS `Python.app` exception. Those branches are validated by synthetic rows only. Before relying on them, run the search over 7 days on a tenant with macOS or Linux EDR and review the `parent_class` and `reasons` columns.

The pre-1.1 process drilldown ran `tstats` without `from datamodel=Endpoint.Processes`, so it always returned 0 rows. The new drilldown returns the CLI launches and their child processes on the host.

**Synthetic tests.** Process rows were run through the full rendered pipeline (from `rename` to the risk-score macro). The earlier round of 35 rows returned the 20 expected rows and none of the 15 expected drops on all four tenants. The rows added in this round, run on Tenant A, gave these results.
- **Kept, with the expected base score:**
  - Claude Code (`node .../claude-code/cli.js`) starting Gemini CLI with `-p`, and a native `claude` starting `gemini -p` (both `ai_agent`, 35).
  - A Node script starting Claude Code `cli.js -p` (automation, 35); Python starting `claude --dangerously-skip-permissions -p` (50); Python starting `llm` (30).
  - A remote VS Code extension host starting Claude Code with `--dangerously-skip-permissions` (40).
  - `codex -a never` and `codex --ask-for-approval never exec` (40); `codex exec --full-auto` from bash (20, headless, no longer bypass).
  - macOS framework Python (`Python.app/Contents/MacOS/Python .../bin/aider --message`) from bash (20).
  - `node /usr/local/bin/qwen -y` (40); `claude -p`, `copilot -p` and native Claude Code `claude -p` from a shell (20); Gemini CLI's self-relaunch carrying `-p` (20).
- **Dropped:**
  - Claude Code's extension CLI (`--output-format stream-json`) and the Codex extension's `codex app-server` under a VS Code Remote extension host (`.vscode-server/.../bootstrap-fork --type=extensionHost`); the same under a Cursor server; the extension CLI under `node` with no parent command line; the extension CLI under JetBrains `remote-dev-server`; `codex.exe app-server` under local `Code.exe`.
  - `fabric -p summarize` and `llm "..."` typed in a shell.
  - Gemini CLI's interactive self-relaunch; the Codex npm shim starting the native `codex`.
  - `codex -p work` (profile, not headless); `claude "run the tests"`; Service Fabric `Fabric.exe`.

### Deployment

The package ships with `enable_alerting: false`. Before you enable it, check three things: `Endpoint.Processes` covers developer workstations and build hosts, `parent_process_name` is populated, and command-line logging is on. Then run the search over 7 days and add sanctioned automation (CI runners, review bots) to `ai_sanctioned_entities`. This rule is risk-only. Enable it as one separately approved change.
