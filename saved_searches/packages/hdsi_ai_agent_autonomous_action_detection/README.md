## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds **AI coding agents and agent frameworks running commands on an endpoint by themselves**. Examples are Claude Code, OpenAI Codex, the GitHub Copilot agent runtime in VS Code, Gemini CLI, Aider, Goose, OpenCode, CrewAI and AutoGen. A user who has handed shell access to an agent has handed it their credentials, network position and write access. Prompt injection, a poisoned repository or a bad plan can then turn into `curl | sh`, a secret read, a scheduled task or a forced push, with no human typing the command. The rule ignores the agents' own start-up probes. It emits at most one low-score `agent_activity` risk event per user and host per day for ordinary agent work, plus a separate risk event for each high-signal category it sees (credential access, persistence, system change). Risk goes on the `user` and the host (`dest`). It creates no notable.

v1.0 looked for children of processes *named* `autogpt`, `crewai`, `langchain`, `autogen` and similar. Python and Node frameworks run as `python`/`node`, so those parent names never occur. Validation found **zero** rows on all four tenants over 30 days. v1.1 keys on the agent runtimes that actually spawn commands. These are `claude.exe`, `codex.exe`, `codex-command-runner-*.exe`, `copilot-runtime.exe` and the agent package paths in `parent_process`.

### Prerequisites
| Data | Fields used | If absent or poor |
|---|---|---|
| `Endpoint.Processes` (accelerated) | `parent_process_name`, `parent_process`, `process_name`, `process` (full command line), `user`, `dest` | No data, no rule. Without `parent_process_name`, agents are invisible, except Claude Code shell snapshots and the Codex sandbox accounts. Without `process`, every command is "routine" and no category can be scored |

- **Parent fields must be populated.** On 2026-10-09 (last 24 h), `parent_process_name` was populated (not `unknown`) on 66.5%, 17.5%, 19.2% and 87.0% of `Endpoint.Processes` events on Tenants A–D, and the `process` command line on 95.7% or more everywhere. Host-inventory sources such as `WinHostMon` carry no parent at all, which is why fill is low on B and C.
- **Windows 4688** puts the parent *image path* in `parent_process`, not its command line. That is enough for native agent binaries such as `...\node_modules\@anthropic-ai\claude-agent-sdk-win32-x64\claude.exe` or `...\@github\copilot-sdk...\copilot-runtime.exe`. It is not enough for frameworks hosted in `python.exe`/`node.exe` (CrewAI, LangChain/LangGraph, AutoGen, Gemini CLI on npm). Those need a parent **command line** from Sysmon EID 1, an EDR or Linux/macOS process telemetry.
- ES lookup `identity_lookup_expanded`, read by both common macros: `ai_risk_multiplier` (bunit sensitivity × privileged) and `ai_unsanctioned_filter(3)`, which takes the user's identity `bunit` as the allow-list *group*. Without identities, only user, host and organisation-wide allow-list keys work. Common package `hdsi_ai_rba_common` is required.

### How it works
- **Scope (`..._agent_scope`, inside `tstats`):** the parent is a known agent binary, or the parent path/command line contains an agent package (`@anthropic-ai…claude`, `@openai…codex`, `@github…copilot`, `@google…gemini-cli`, `crewai`, AutoGen package names such as `autogen_agentchat`/`pyautogen`, `langgraph`, `langchain`, `openhands`, `swe-agent`, `smolagents`, `metagpt`). Claude Code shell snapshots (`.claude/shell-snapshots`) in the child command line also match, and so do processes running as the Codex Windows sandbox accounts (`CodexSandbox*`). The bare names `copilot`/`copilot.exe` (GitHub Copilot CLI) are excluded when the binary lives under `WindowsApps` or a `Microsoft.Copilot` path. AutoGen matches only by package name, so GNU autotools `autogen.sh` builds do not. `tstats` matching is case-insensitive.
- **Agent label and provider:** `agent_tool` and `provider` come from the parent name/path. These provider strings are the common registry names, so allow-list keys written for the network detections apply here too: `Anthropic` (Claude Code, Claude desktop), `OpenAI` (Codex), `GitHub Copilot`, `Google Gemini` (Gemini CLI), `Cursor` (Cursor Agent), `Amazon Q` (`qchat`), `Kiro` (`kiro-cli`), `Aider`. Every other agent uses its own label as the provider (`Goose`, `OpenCode`, `Cline`, `OpenHands`, `CrewAI`, `AutoGen`, `LangChain`, `SWE-agent`, `smolagents`, `MetaGPT`, `AutoGPT`, `Open Interpreter`, `AI agent`). Those labels are package-local: write allow-list keys with exactly that string (lower-cased), e.g. `*|crewai`.
- **Probe removal:** `..._housekeeping(2)` drops start-up noise seen in validation: `conhost`, `where.exe`, bare version checks, Claude Code's PowerShell-version, policy-registry and MachineGuid reads, IDE detection through `tasklist | findstr`, process-age lookups and read-only git context calls. Every probe is **anchored to its full observed command shape** (the executable, the probe and nothing else). A command that only *contains* a probe fragment, such as `if ($PSVersionTable.PSVersion.Major -ge 5) { iwr … | iex }` or `curl … -o a.sh -v`, is still categorised. Git probes accept only `-C <path>`, `--no-optional-locks` and the agents' own `core.hooksPath`/empty `core.fsmonitor` overrides, so `git -c core.fsmonitor=<program> status` is kept.
- **Self-spawns:** a child with the same name as its parent is dropped (Claude's embedded ripgrep, Electron helpers, `copilot-runtime` workers), **except** when the parent is a shell or script host (`powershell`, `pwsh`, `cmd`, `bash`, `sh`, `zsh`, `node`, `python`…). So `powershell.exe -Command "…"` started by PowerShell under a Codex sandbox account, or `node build.js` started by Claude Code on npm, is categorised.
- **Claude desktop MCP launches:** a Claude desktop child that is an MCP launcher (`npx`, `uvx`, `uv`, `node`, `docker`, `python`, `bun`, `deno`, or `cmd /c npx …` with no chained command) **and** whose name or command line contains `mcp` or `modelcontextprotocol` is dropped. That is exactly the set `hdsi_ai_mcp_server_execution` matches. Any other Claude desktop child, such as `python -c …`, `node -e …` or `docker run --privileged …`, is categorised here.
- **Categorisation:** `..._categorize(1)` tags each remaining command line (lower-cased, `\` folded to `/`). Categories are split into a **high-signal** tier, each scored as its own risk event, and a **development** tier, which only raises the daily activity event:

  | Tier | Category | Examples | Not matched | ATT&CK emitted |
  |---|---|---|---|---|
  | High-signal | `credential_access` | `.env`, `.env.local`, `~/.aws/credentials`, `~/.ssh/id_*`, `.npmrc`, `cmdkey`, `gh auth token`, `az account get-access-token`, keychain, browser `Login Data` | `.env.example`/`.sample`/`.template`/`.dist`, and `cp .env.example .env` | T1552 |
  | High-signal | `persistence` | `schtasks /create`, `Register-ScheduledTask`, `crontab -e`, `crontab -u <user> -e`, `crontab <file>`, `… \| crontab -`, `launchctl load`, `systemctl enable`, Run keys, `New-Service`/`sc create` | `crontab -l` | T1053 for scheduled tasks and crontab only. Services, launchd/systemd and Run keys (T1543/T1547) carry T1059 only, because the annotation is limited to four IDs |
  | High-signal | `system_change` | `sudo`, `runas`, `Set-MpPreference`, `netsh firewall`, `net localgroup administrators /add`, `reg add`, `Set-ExecutionPolicy Bypass`, `vssadmin` | | T1059 |
  | Development | `network_transfer` | `curl`, `wget`, `scp`, `rclone`, `Invoke-WebRequest`, `DownloadString`, `certutil -urlcache`, `git push` | | T1105 only for **downloads** by `curl`, `wget`, `bitsadmin`, `iwr`/`irm`, `DownloadString`/`DownloadFile`, `Start-BitsTransfer`, `certutil -urlcache`, `Net.WebClient`. Uploads (`curl -d/-F/-T/--data/--upload-file/-X POST\|PUT`, `wget --post-*`, `-Method Post`, `-InFile`, `UploadFile`) and `git push`, `scp`, `rsync`, `rclone` carry T1059 only |
  | Development | `destructive` | `rm -rf`, `Remove-Item -Recurse`, `rd /s`, `git reset --hard`, `git clean -f`, `git push --force`, `DROP TABLE` | | T1059 |
  | Development | `package_install` | `pip install`, `uv add`, `uvx`, `npm install <pkg>`, `npx -y …`, `npx -p …`, `npx <pkg>@<ver>`, `npx create-…`, `pnpm dlx`/`yarn dlx`, `winget`/`choco`/`brew`/`apt install` | `npx jest`, `npx tsc -p .`, `npx prettier` (local tools) | T1059 |

- **Risk objects:** service, machine and sandbox accounts (`SYSTEM`, `NT AUTHORITY\*`, `HOST$`, `unknown`, `CodexSandbox*`) are nulled, so they never become a user risk object. The sandbox account is kept as `sandbox_user` and shown in `user_display`. Rows with neither a user nor a host are dropped. `dest_display` reads `n/a (no host)` when the host is empty. The drilldowns use `user_dd`/`dest_dd`, copies with `\` and `"` replaced by `*`, so `DOMAIN\user` values still match.
- **Aggregation:** one row per `user` + `dest` + `agent_tool` per hour. It carries `action_count` (distinct non-probe command lines), `event_count` (executions), `action_categories`, `child_processes`, `agent_process` and per-category command lists.
- **Risk events (`risk_category`):** each row is expanded into one result per risk category:
  - `agent_activity` when `action_count >= ..._min_actions` (default 3) **or** any development category is present. Score `10 + 5` per development category, so 10 to 25. `risk_multiplier` is **not** applied: ordinary developer work is not amplified for sensitive business units. `risk_tier` is `routine` or `development`.
  - One result per high-signal category present: `credential_access` 25, `persistence` 30, `system_change` 25, each × `risk_multiplier` and capped at 60. `risk_tier` is `sensitive`.
  - `risk_score` applies to both risk objects. The literal `_risk` scores (10/10) are only the fallback.
- **`command_sample` and `mitre_attack` are per result:** a `credential_access` result shows up to three credential commands and T1059 + T1552. A `persistence` result shows persistence commands and adds T1053 only if one of them is a scheduled task or crontab. `agent_activity` shows development commands first, then routine ones, and adds T1105 only if one of them is a download. The PowerShell launcher prefix and GitHub Copilot's PowerShell wrapper are stripped. Inline secrets are redacted before the sample reaches the risk index: `Authorization: Bearer|Basic|Token …`, `x-api-key:`, `password=`/`token=`/`api_key=`/`secret=`-style pairs, `--password`/`--token`/`--api-key`/`--secret` values, and literal `sk-…`, `ghp_…`/`github_pat_…`, `xox?-…`, `AKIA…` and JWT strings become `[redacted]`. Categorisation runs on the unredacted command line.
- **Cadence and suppression:** hourly (`-65m@m` to `-5m@m`). Suppression is 24 h on `user,dest,risk_category`. This deliberately adds `risk_category` to the risk-object fields. Each category is counted **at most once per user and host per day**: there is no double counting when the category mix changes, and an early `agent_activity` event cannot hide a later `.env` read or `schtasks /create`. A second agent on the same host on the same day is inside the same suppression key, so the first agent seen names the event.

### Daily risk budget against the aggregators
Per user, per host, per 24 h, from this rule alone (`risk_multiplier` 1.0):

| Agent behaviour that day | Events | User risk |
|---|---|---|
| Routine commands only | `agent_activity` | 10 |
| + package installs, `git push`, downloads, `rm -rf build` | `agent_activity` | up to 25 |
| + reads `.env` or another secret file | + `credential_access` | up to 50 |
| + `sudo`/`reg add`/firewall change | + `system_change` | up to 75 |
| + scheduled task / crontab / service | + `persistence` | up to 105 |

`hdsi_rba_ai_user_risk_threshold_exceeded` (medium, default 60) needs at least **two distinct** HDSI AI detections, so this rule alone never triggers it. `hdsi_rba_ai_user_critical_risk_threshold_exceeded` (default 90) can be reached by this rule alone only when one agent session on one host combines secret access, a system change and persistence, or by a user with a high `risk_multiplier` (high-signal events cap at 60 each). A developer whose agent reads `.env` every day adds 35–50 per host per day. A developer working on several hosts adds that budget once per host.

### Allow-listing sanctioned agents
Sanctioned agent use is allow-listed in the common `ai_sanctioned_entities` lookup, not by editing this package. The allow-list applies **only to `agent_activity` events**. Credential access, persistence and system-change events by a sanctioned agent are still scored, because those are the actions a prompt-injected or misdirected agent takes. Keys (`allow_key` = lower-cased `<entity>|<provider>`, provider strings as listed under *How it works*):

| Scope | Key example | Works here when |
|---|---|---|
| One user | `lab\jdoe\|github copilot` or `jdoe@corp.example\|*` | The `user` value matches exactly (lower-cased) |
| One host | `build-01\|anthropic` | The `dest` value matches exactly |
| A group | `engineering\|anthropic` | The user's ES identity `bunit` is `Engineering` (whole value, lower-cased). The search carries no `user_group`/`category` field, so the identity bunit is the only group source. It is looked up from the raw user value, then the bare name (`DOMAIN\` and `@suffix` stripped). Users without an identity, and Codex sandbox rows, have no group |
| Whole organisation | `*\|github copilot` | Always (any user or host) |

To silence a host or account **completely**, including the high-signal events (for example a CI runner whose agent legitimately runs `sudo`), use `..._filter` (`NOT Processes.dest IN ("ci-runner-*")`) or `..._customizations` (`search NOT (dest="ci-runner-01" risk_category="system_change")`).

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_agent_autonomous_action_detection_filter` | `()` | Exclusions inside the `tstats` where clause (`Processes.*` names), e.g. `NOT Processes.dest IN ("ci-runner-*")` |
| `hdsi_ai_agent_autonomous_action_detection_agent_scope` | Agent binaries, agent package paths, shell snapshots, Codex sandbox users | Which parents count as an AI agent. Add in-house agent launchers here |
| `hdsi_ai_agent_autonomous_action_detection_housekeeping(2)` | Observed start-up probes, anchored to their full command shape | Eval condition (true = ignore). Add new probe shapes here, anchored with `^…\z`, rather than raising the threshold |
| `hdsi_ai_agent_autonomous_action_detection_categorize(1)` | Six regex categories | Command classifier. Tiers and weights live in the search |
| `hdsi_ai_agent_autonomous_action_detection_min_actions` | `3` | Distinct non-probe commands per user/host/agent per hour before a routine `agent_activity` event is emitted |
| `hdsi_ai_agent_autonomous_action_detection_customizations` | `search *` | Post-scoring hook, one row per `risk_category` (fields: `user`, `dest`, `user_display`, `dest_display`, `agent_tool`, `provider`, `risk_category`, `risk_tier`, `action_count`, `event_count`, `action_categories`, `high_categories`, `dev_categories`, `action_category_list`, `mitre_attack`, `command_sample`, `sandbox_user`, `risk_multiplier`, `risk_score`) |
| `hdsi_ai_agent_autonomous_action_detection_risk_score` | `search *` | Last pipe. Rescale or override `risk_score` here |

### Threshold
`..._min_actions` gates only *routine* `agent_activity`. Development categories emit `agent_activity` regardless, and high-signal categories always emit their own events. Derive the value from 30 days of agent-hours on the tenant:

```spl
| tstats summariesonly=t allow_old_summaries=t count from datamodel=Endpoint.Processes
    where `hdsi_ai_agent_autonomous_action_detection_agent_scope` earliest=-30d
    by _time span=1h Processes.user Processes.dest Processes.parent_process_name Processes.process_name Processes.process
| rename Processes.* as *
| eval cmd_n=replace(lower(process),"\x5c","/"), process_name_lc=lower(process_name), parent_lc=lower(parent_process_name)
| where NOT ((process_name_lc=parent_lc AND NOT match(parent_lc,"^(powershell|pwsh|cmd|bash|sh|zsh|dash|fish|node|python[0-9.]*|pythonw|py)([.]exe)?\z")) OR `hdsi_ai_agent_autonomous_action_detection_housekeeping(cmd_n,process_name_lc)`)
| stats dc(cmd_n) as actions sum(count) as executions by _time user dest parent_process_name
| stats count as agent_hours p50(actions) as p50 p90(actions) as p90 max(actions) as max max(executions) as max_exec by parent_process_name
```

Keep the default of 3 while agent use is rare (fewer than ~20 agent-hours a day). Where agents are part of daily engineering, the routine event is already bounded to one per user and host per day, so raising the value mainly removes users who only touch an agent briefly; set it to about the p50. Do not raise it above 10: a session that runs more than 10 distinct commands in an hour is exactly the autonomy this rule exists to show.

`actions` counts distinct **full command lines**. Where `process` is truncated, many different agent commands collapse into one value. On Tenant C, 11 GitHub Copilot `pwsh` executions in one hour collapsed to a single distinct (truncated) command line, and the hour reached 3 only because of three distinct `rg` searches. If `max_exec` is much larger than `max` for an agent, your command lines are being truncated: lower `..._min_actions` for that tenant, or fix the truncation at the source (check whether the add-on, forwarder or data model extraction shortens the command line).

### Known false positives / Limitations
- **Agent use is legitimate.** Most results will be developers doing their jobs. That is why ordinary work is one 10–25 point event per user and host per day (see *Daily risk budget*) and only the high-signal categories score more.
- **Categories are command-line heuristics.** `cat .env` by a coding agent is common, and it is also the exact secret-exposure path that matters, so it stays high-signal. `rm -rf build`, `npm install <pkg>` and `git push` are normal development steps and only raise the daily activity event. `npx <tool> -p …` with `-p` *after* the tool name is not an install; `npx -p <pkg> <tool>` is.
- **Grandchildren are not followed.** A command run inside a shell the agent opened is visible only through that shell's command line (`bash -c "..."`, `pwsh -Command "..."`). A script launched by the agent that then spawns its own tools shows only the first hop.
- **Truncated command lines.** On one tenant, `process` was truncated at about 400 characters. GitHub Copilot's PowerShell wrapper alone fills that space, so the agent's real command was cut off and could not be categorised. Those sessions score as routine, and their executions collapse into one distinct command for `action_count` (see Threshold).
- **Codex on Windows** runs commands as a local sandbox account (`CodexSandboxOffline`/`CodexSandboxOnline`). The human user is not in the event, so only the host receives risk, and only host or organisation-wide allow-list keys apply.
- **Python/Node-hosted frameworks** (CrewAI, LangChain, AutoGen, Gemini CLI from npm) are invisible with Windows 4688 alone. See Prerequisites.
- **Claude desktop** shares the `claude.exe` name. It is labelled `Claude desktop` when the install path is the desktop app. Only its self-spawns and MCP-named server launches are dropped; every other child is categorised. This branch is **not validated live**: no tenant had a process under a Claude desktop parent in 30 days. An MCP server that itself runs commands is a grandchild and is not followed here.
- **Framework substrings.** `crewai`, `langchain`, `langgraph`, `openhands`, `swe-agent`, `smolagents` and `metagpt` match anywhere in the parent command line. A developer running tests from a checkout of one of those projects (e.g. `python …/langchain/tests/…`) is labelled as that framework. None of these substrings occurred on the four validation tenants in 30 days; add `NOT Processes.parent_process IN (…)` exclusions in `..._filter` if they do on yours.
- **Copilot naming.** Microsoft 365 Copilot, the Edge Copilot host, SSMS Copilot and the Visual Studio `copilot-language-server` all appear in validation data. None of them match: scope uses the exact names `copilot-runtime*` and `copilot`/`copilot.exe` (the latter excluded under `WindowsApps`/`Microsoft.Copilot` paths).
- **Command-line redaction is pattern-based.** It catches the common header, flag, `key=value` and well-known token formats. A secret passed positionally (e.g. `mysql -pS3cret`) is not recognised and can appear in `command_sample`.
- **IDE terminals are out of scope.** A user typing in the VS Code or Cursor terminal is a `Code.exe`/`Cursor.exe` child, not an agent child, and is not matched. An agent that runs its commands through the IDE's integrated terminal, rather than through its own runtime process, looks the same and is also not seen. Add its launcher to `..._agent_scope` if your telemetry can tell it apart.

### Validation
Read-only tests on 4 production ES tenants on 2026-10-09. Parent and command-line fill are measured over the 24 h before the test; agent-spawned and kept counts over the 30 days before it (rolling, so they drift as agent use changes). Results of the final version (per-category risk events): parse of the rule and both drilldowns on A–D, a 4 h run on A–D and a 7 d run on Tenant C. The 30 d counts come from the previous round, before the risk events were split by category; the probe filter and scope are unchanged since then except for the self-spawn and Claude desktop refinements, which add rows rather than removing them, and the 7 d result on C did not change.

| Tenant | Endpoint.Processes (24 h) | Parent fill / command-line fill (24 h) | Agent-spawned (30 d) | Kept after probe filter (30 d) | Parses (rule + 2 drilldowns) | Results: 4 h / 7 d | Notes |
|---|---|---|---|---|---|---|---|
| A | ~174M, Windows Security 4688 | 66.5% / 99.9% | 0 | 0 | OK | 0 / – | VS Code terminals present (`Code.exe` children). Only Edge's Copilot host matches `*copilot*`, and it is out of scope. No agent runtimes |
| B | ~51k, Windows XML events | 17.5% / 100% | 1 (Codex command runner, sandbox account) | 1 | OK | 0 / – | One routine Codex command editing a config file. Below threshold, and the user is the sandbox account |
| C | ~156M, Windows 4688 + host-inventory monitor | 19.2% / 95.7% | 243 (Copilot agent runtime 208, Claude agent SDK 34, Codex 1), 4 hosts, 6 users | 14 executions, 4 distinct (all Copilot) | OK | 0 / 1 | All 34 Claude and the Codex child were probes or self-spawns. The one 7 d result is a GitHub Copilot `agent_activity` event, `routine`, 4 actions (14 executions), score 10 |
| D | ~210k, Windows 4688 | 87.0% / 99.9% | 0 | 0 | OK | 0 / – | No developer agent activity |

All runs completed with no FATAL or ERROR message (`–` = not re-run this round; 0 in the previous round's 7 d and 30 d runs). v1.0 baseline on the same tenants: parses, 0 rows everywhere, because its framework parent names never occur.

No tenant has high-signal or development-category agent activity, so the scoring was verified with synthetic `makeresults` runs of the full pipeline (everything after `tstats`, with the real common macros and lookups) on Tenant C:
- One Claude Code session on one host with `cat .env`, `git push`, `npm install`, `npx jest`, `cp .env.example .env`, `crontab -u bob -e`, a `curl -d @~/.aws/credentials` upload, a `curl -fsSL … -o a.sh` download and `node build.js` gave three results: `agent_activity` (`development`, 20: network transfer and package install; T1059 + T1105; sample starts with the download), `credential_access` (25; T1059 + T1552; sample is the `.env` read and the credential upload) and `persistence` (30; T1059 + T1053; sample is the crontab edit). `npx jest` and `cp .env.example .env` were not categorised, and `node build.js` under a `node` parent was kept.
- Uploads only (`curl -T`, `wget --post-file`, `curl -d @…`) gave `agent_activity` with T1059 only; a `curl -X GET … -o` download gave T1105.
- `npx tsc -p .` and `npx prettier` stayed routine; `npx -p typescript tsc`, `npx --yes foo`, `npx cowsay@1.5.0`, `npx -y create-foo` and `pnpm dlx` were `package_install`. `.env.local` was credential access, `.env.sample` copies were not. `crontab -` and `crontab -u bob <file>` were persistence, `crontab -l` was not.
- A Codex sandbox `powershell.exe` → `powershell.exe -Command "reg add HKCU…"` gave a host-only `system_change` result (25), with the sandbox account in `user_display`.
- Claude desktop `python -c`, `node -e` and `docker run --privileged` children gave a routine `agent_activity` result (10). Its `npx -y @modelcontextprotocol/…` and `uvx mcp-server-git` launches and its `claude.exe` self-spawn produced nothing.
- The high-signal results passed through `ai_unsanctioned_filter` unchanged (their allow keys are the placeholder `__high_signal__`, which no lookup row can match); `user_dd` showed `DOMAIN*user` for a `DOMAIN\user` value.
- Earlier rounds verified the probe shapes (PowerShell version, `tasklist | findstr`, MachineGuid, policy registry, process age, `git remote -v`/`ls-files` with `-C`, `--version`), that compound commands containing probe fragments are still scored, the secret redaction (`Bearer` token, `sk-…` key) and the AutoGen label. That code is unchanged.

### Deployment
The package ships with `enable_alerting: false`. Before enablement, confirm that the target tenant's `Endpoint.Processes` populates `parent_process_name` and the full `process` command line. Run the Threshold search to see whether any agent runtimes appear and set `..._min_actions`. Check the *Daily risk budget* against the tenant's aggregator thresholds. Add allow-list entries for sanctioned agent programmes to `ai_sanctioned_entities` (they quiet `agent_activity` only; see *Allow-listing sanctioned agents*). The rule is risk-only (no notable). Enabling it is a separately approved change.
