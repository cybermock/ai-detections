## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule detects an AI coding agent launching remote-access or remote-execution commands. Covered agents include Claude Code (npm and native installs), Codex (including its Windows command runner), Gemini CLI, Google Antigravity agent terminals, GitHub Copilot CLI and the Copilot agent runtime in VS Code, Aider, Amazon Q, OpenCode and similar tools. Covered commands include SSH, PsExec, WinRM/PowerShell remoting, RDP, `wmic /node:`, `net use \\host`, admin-share paths (`\\host\c$`, `\\host\admin$`), and offensive frameworks such as Impacket and NetExec. An agent runs with a developer's credentials and can reach other hosts, so a prompt injection or misuse can turn it into a pivot point, and its commands run without a human typing them. The rule creates risk on the user and on the source host (`src`, where the agent ran). It does not create a notable.

### Prerequisites
- **CIM `Endpoint.Processes` (accelerated)** with `parent_process_name`, `process` (full command line), `dest` and `user` populated. EDR sources such as Sysmon EID 1, CrowdStrike, Defender for Endpoint and SentinelOne normally map all of them.
  - `parent_process` (the parent command line) is needed for agents that are not identified by the parent name alone: `node`/`bun`/`python` hosts (npm installs of Claude Code or Gemini CLI, Aider, Cline), the Claude Code native installer (see below) and Google Antigravity agent shells.
  - If `parent_process_name` is missing, the rule cannot attribute anything to an agent and returns nothing.
  - If `process` is empty, the remote-access regex has nothing to match and the rule returns nothing.
- **ES identity lookup `identity_lookup_expanded`** (optional). `ai_unsanctioned_filter` looks up the user's `bunit` itself (raw user value, then the bare name) so that business-unit allow-list rows work, and the rule adds `bunit` to the output for context. If it is missing or `bunit` is empty, only user, host and organisation-wide allow-list rows apply.
- **Common package `hdsi_ai_rba_common`:**
  - `ai_unsanctioned_filter(3)`, with the allow-list in `ai_sanctioned_entities`.
  - The `ai_tool_processes` lookup, which labels the tool and provider. It is read twice: by the parent process name, then by the tool name derived from the parent command line (node/bun/python hosts, the Codex runner, Antigravity), so `provider` uses the same strings as the rest of the AI-RBA content.

### How it works
- **One `tstats` over `Endpoint.Processes`.** It keeps only processes whose **parent** is an AI coding agent (`hdsi_ai_assisted_lateral_movement_agent_parents`). The parent can be any of the following:
  - A native agent binary.
  - A versioned agent command runner. Codex on Windows runs every command through `codex-command-runner-<version>.exe`. The Copilot agent in VS Code uses `copilot-runtime.exe` and `copilot-language-server.exe`.
  - A `node`, `bun` or `python` host whose command line names the agent. This can be the package path from a Windows npm shim, or a Unix bin shim such as `node /usr/local/bin/claude`.
  - The Claude Code **native installer**. Its binary lives in `~/.local/share/claude/versions/<version>`, so an EDR that reports the resolved image logs the parent name as the version string (for example `2.0.30`). The rule therefore also matches on the parent command line: `claude`, `claude ...`, `*/claude/versions/*` or `~/.local/bin/claude`.
  - A **Google Antigravity** agent terminal: a `zsh`/`bash`/`pwsh`/`cmd` parent whose command line runs from `~/.gemini/antigravity/`.

  Agents run each command through a shell (`zsh -c ... eval '...'`, `bash -lc`, `pwsh -Command`, `cmd /c`). The shell is the agent's direct child, and its command line holds the whole command the agent wrote, including loops, conditionals and multi-line scripts. The inner `ssh` that the shell forks is a grandchild and is never needed. The link is causal, not a time-window coincidence.
- **Benign fragments are stripped first.** Each child command line is lowercased, and fragments that match `hdsi_ai_assisted_lateral_movement_benign_regex` are replaced with a space. The benign fragments are:
  - ssh whose destination is exactly a public code host (`github.com.evil-c2.net` is not stripped, and neither is a `-J`/`ProxyJump` hop in front of it), or whose remote command is `git-upload-pack`, `git-receive-pack` or `git-lfs`. This is git transport, so it covers any Git server.
  - ssh to localhost, unless another remote client follows in the same command (`ssh localhost -t "ssh db01"` is still caught).
  - Version, help and query-only invocations: `ssh -V`/`-v`, `ssh -G host`, `ssh -Q cipher`, and `--help`, `-h`, `/?` of ssh, scp, plink, PsExec, winrs, mstsc and similar clients. Offensive tools are not stripped on `--help`.
  - Text, not commands: quoted `git`/`gh` messages (`-m`, `--message`, `--body`, `--title`) and the body of a `cat`/`tee` heredoc. This covers Claude Code's `git commit -m "$(cat <<'EOF' ... EOF)"` pattern, whose message lines can start with "ssh". A double-quoted message that contains `$` or a backtick is kept, because it can run a command. A heredoc fed to a shell (`bash <<EOF`) is kept.
  - `-ComputerName .`, `localhost` or `$env:COMPUTERNAME`, `wmic /node:localhost`, and `\\localhost`.

  Because only the fragment is removed, a real hop elsewhere in the same command line is still caught. For example, `ssh -T git@github.com; ssh admin@10.x` is caught, and so is `ssh admin@10.x 'git pull git@github.com:...'`.
- **The remainder is tested against `hdsi_ai_assisted_lateral_movement_remote_regex`.** The regex enforces these rules:
  - Remote clients (ssh, sftp, plink, PsExec/PAExec, winrs, RDP clients, smbclient, nxc) must be in **command position**. That means one of the following comes first:
    - the start of the line, a newline, `; & | ( { !` or a backtick;
    - a shell's `-c` (`bash -lc`, `zsh -c`, `pwsh -c`), `-Command` or `cmd /c`;
    - the shell keywords `do`, `then`, `else`, `elif` (`for h in ...; do ssh $h ...; done`);
    - a wrapper: `eval`, `exec`, `sudo`, `doas`, `xargs`, `env`, `nohup`, `nice`, `timeout`, `time`, `start`, `runas`.

    Up to four wrapper options, `VAR=value` assignments or durations may come in between (`sudo -u deploy ssh`, `xargs -I{} ssh`, `env SSH_AUTH_SOCK=x ssh`, `timeout -k 5 10 ssh`). The client may be quoted or path-qualified. So `which ssh`, `command -v ssh`, `grep -c ssh`, `man ssh` and `ls /etc/ssh` do not match.
  - `scp`, `pscp` and `rsync` need a `host:` argument.
  - `net use`, `sc` and `reg` need a `\\host` argument. `schtasks` needs `/s host`. `reg ... /s` is a recursive query and is not treated as a remote host.
  - Any admin-share path `\\host\c$`, `\\host\admin$` or `\\host\ipc$` matches, whatever the command (`copy`, `dir`, `Copy-Item`). This is the usual staging step before PsExec-style execution. Ordinary shares such as `\\fs01\public` do not match.
  - PowerShell WMI/CIM/remoting cmdlets and their aliases (`icm`, `gwmi`, `gcim`, `iwmi`) need `-ComputerName` (or `-cn`, `-comp`). `Enter-PSSession`/`New-PSSession` (`etsn`, `nsn`) need a host or `-ComputerName`/`-HostName`, so `Enter-PSSession -ComputerName localhost` and `-Id 3` do not match.
  - Impacket, NetExec, CrackMapExec and evil-winrm match anywhere.
- **Derived fields.** The rule sets the following fields:
  - `remote_method`: ssh, smb, winrm, rdp, wmi, cloud_shell or other. `gcloud compute ssh` and `az ssh` count as cloud_shell only, not also as ssh.
  - `remote_targets`: best effort, taken from `user@host`, `ssh [opts] host` (options that take a value, such as `-l user`, `-p port`, `-i key`, `-o opt`, are skipped), `/v:`, `/node:`, `\\host`, `-ComputerName`, `schtasks /s`, `winrs -r:`, `--target` and `az ssh vm --ip`. Public code hosts and localhost are removed from the list. A host held in a shell variable (`ssh $h`) is not resolved.
  - `remote_commands`: the first 5 matching command lines, 300 characters each, with obvious credentials replaced by `<redacted>`: `sshpass -p`, plink `-pw`, `--password`/`-password`, `net use ... /user:x <password>`, `-u x -p <password>`/`-H <hash>`, `-hashes`, `-aesKey`, `ConvertTo-SecureString '<text>'`, and `user:<password>@host`.
  - `offensive_tooling=1` for Impacket, NetExec/CrackMapExec and evil-winrm.
- **Filtering, before aggregation.** `ai_unsanctioned_filter(user,src,provider)` runs on each agent-parent row, with that row's own provider, and drops sanctioned users, hosts, business units and organisation-wide `*|<provider>` entries. So when one user runs two agents on a host, each agent is allowed or kept on its own.
- **Aggregation.** Results are then aggregated per `user` and `src`. `provider` lists every agent provider seen, and `bunit` is added from `identity_lookup_expanded`. Some accounts are not personal: null, "unknown", and the Codex Windows sandbox accounts (`CodexSandbox*`, also as `HOST\CodexSandbox*`). Their rows still produce host risk but no user risk object, so a shared service account cannot become a false RBA hotspot.
- **Scoring.** The literal `_risk` scores are user 50 and system 40. `risk_score=70` is set only when offensive tooling is present, and it overrides both objects. There is no identity multiplier: one agent-driven remote command, after the benign stripping above, is already a specific event.
- **MITRE.** `mitre_attack` is set per method:
  - T1021.004 for SSH.
  - T1021.002 for SMB and admin shares (PsExec, `net use`, remote `sc`/`reg`/`schtasks`).
  - T1021.006 for WinRM (PowerShell remoting, CIM cmdlets, winrs).
  - T1047 for WMI (`wmic /node:`, `Get-WmiObject`/`Invoke-WmiMethod -ComputerName`, wmiexec).
  - T1021 for RDP and cloud remote shells.

  The annotation lists the same five IDs. This is one more than the usual limit of four. Each ID maps to a distinct `remote_method`, and the common `ai_mitre_mapping.csv` is generated from these annotations.
- **Schedule.** The rule runs every 5 minutes over `-15m@m` to `-5m@m`. Suppression is 1 hour on `user,src`.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_assisted_lateral_movement_filter` | `()` | Exclusions inside the tstats `where` clause, using Endpoint field names, e.g. `NOT Processes.dest IN ("jump-*")`. |
| `hdsi_ai_assisted_lateral_movement_agent_parents` | Agent binaries, versioned runners (`codex-command-runner*`, `copilot-runtime*`, `copilot-language-server*`), node/bun/python hosts matched on package path or bin shim, the Claude Code native install (parent command line), and Antigravity agent shells | Defines which parent processes count as an AI coding agent. Add new agent binaries here. Prompt-only CLIs (fabric, llm, mods, openai) are deliberately excluded. |
| `hdsi_ai_assisted_lateral_movement_remote_regex` | Command-position SSH/SMB/admin-share/WinRM/RDP/WMI/Impacket/cloud remote-shell regex | What counts as remote access in a child command line, after benign fragments are stripped. |
| `hdsi_ai_assisted_lateral_movement_benign_regex` | Git transport over SSH, localhost, version/help/query-only invocations, git/gh messages and cat/tee heredoc bodies, local `-ComputerName`, `/node:` and `\\` | Fragments removed before matching. Add internal Git hosts or sanctioned jump hosts, anchored to the ssh destination and ending in `(?![\w.-])` so that `jump01.evil.net` is not stripped: `\bssh(?:\.exe)?\s+(?:[\w.-]+@)?jump01(?![\w.-])` (regex form; double each backslash inside the macro's quoted definition, and add it as a new alternative). |
| `hdsi_ai_assisted_lateral_movement_customizations` | `search *` | Post-normalisation filter. Fields: `user`, `src`, `bunit`, `ai_tools`, `agent_processes`, `provider`, `remote_methods`, `remote_targets`, `remote_commands`, `offensive_tooling`. |
| `hdsi_ai_assisted_lateral_movement_risk_score` | `search *` | Last pipe. Override `risk_score` per tenant (keep it at or below 100). |

Some teams' agents manage servers by design, for example platform or SRE engineers who use Claude Code over SSH. To allow-list them, add rows to `ai_sanctioned_entities` in the common package. Do not widen the benign regex for this. The key's provider part is the lowercased `provider` value of the agent, taken from `ai_tool_processes`:

| Agent | `provider` (allow-list key uses it lowercased) |
|---|---|
| Claude Code | `Anthropic` |
| Codex, Codex command runner | `OpenAI` |
| Gemini CLI, Antigravity | `Google Gemini` |
| Copilot CLI, Copilot runtime / language server | `GitHub Copilot` |
| gh-copilot | `Microsoft Copilot` |
| Amazon Q / qchat | `Amazon` |
| OpenCode, Cursor Agent, Aider, Cline, Qwen Code, Goose, Kiro, Amp | `OpenCode`, `Cursor`, `Aider`, `Cline`, `Alibaba Qwen`, `Goose`, `Kiro`, `Sourcegraph` |
| An agent the lookup does not know | `AI coding agent` |

Examples: `<user>|anthropic` allows one user's Claude Code, `<user>|*` allows every agent for that user, `<host>|*` allows a jump host, `<bunit>|*` allows a team, and `*|github copilot` allows Copilot agents organisation-wide. Check the `provider` field of a preview run before you write a key.

### Threshold
The rule has no numeric threshold. Every agent-launched remote command counts. Before you enable it, run this query over 7 days to see which agents run on your endpoints and what they launch:

```spl
| tstats summariesonly=t allow_old_summaries=t count dc(Processes.dest) as hosts dc(Processes.user) as users
    from datamodel=Endpoint.Processes where `hdsi_ai_assisted_lateral_movement_agent_parents`
    by Processes.parent_process_name Processes.process_name
| sort - count
```
To see which shell and remote-tool command lines in your environment the regex would flag, independent of AI agents, run this over 1 hour:

```spl
| tstats summariesonly=t allow_old_summaries=t count from datamodel=Endpoint.Processes
    where Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash","zsh","sh","reg.exe","ssh","ssh.exe","net.exe","sc.exe","wmic.exe","mstsc.exe")
    by Processes.process_name Processes.process
| rename Processes.* as *
| eval p=replace(lower(process), `hdsi_ai_assisted_lateral_movement_benign_regex`, " ")
| where match(p, `hdsi_ai_assisted_lateral_movement_remote_regex`)
| stats sum(count) as events by process_name p | sort - events
```
Everything it returns should be a genuine remote operation. If a local command shows up, extend the benign regex.

### Known false positives / Limitations
- **Sanctioned DevOps use.** Engineers who let an agent SSH into servers they administer will trigger this rule. That is intended visibility, not noise. Allow-list them by user, host or `bunit`.
- **Self-hosted Git.** Git transport (`git-upload-pack`, `git-receive-pack`, `git-lfs`) is excluded for any host. An interactive `ssh -T git@git.internal` auth test is excluded only for public code hosts, so add internal Git hosts to the benign regex. An attacker who wraps a real command inside a fake `git-upload-pack` remote command is not caught.
- **Process-name collisions.** An earlier version keyed on bare names like `fabric.exe`. In one validation tenant, `Fabric.exe` was Microsoft Service Fabric (about 9k launches/day on 3 hosts), not the Fabric AI CLI. This version only trusts *agentic* CLIs and their runners, and only as the parent process.
- **Non-personal accounts.** Codex on Windows runs commands as a local sandbox account (`CodexSandbox*`), as seen in Tenant B. Those rows create host risk only, so the human user must be resolved from the host.
- **Indirection is missed.** These cases are not visible in the child command line:
  - A remote command inside a script file the agent runs (`bash deploy.sh`). Commands the agent writes inline, including loops, `if` blocks and multi-line scripts, are visible.
  - A remote host held in a variable or file is detected, but `remote_targets` shows "not parsed" (`for h in $(cat hosts); do ssh $h ...`).
  - A command run through an MCP server process.
  - Commands sent to an editor's integrated terminal (see Other agent IDEs below). Copilot commands launched directly by `copilot-runtime.exe` are covered.
- **Unix node-hosted and native agents.** Coverage depends on the parent command line naming the bin shim (`/bin/claude`, `/bin/gemini`, `/bin/codex`, `/bin/copilot`, `/bin/qwen`, `/bin/opencode`, `/bin/cursor-agent`, `/bin/cline`, `/bin/amp`) or the package. For the Claude Code native installer, the EDR must report either the parent name `claude` or a parent command line that starts with `claude` or contains `claude/versions/`. An agent started through a custom alias or wrapper path is missed. None of the validation tenants had macOS or Linux Claude Code processes, so these paths are proven only by synthetic tests.
- **Other agent IDEs.** Antigravity agent terminals are covered. Cursor and Windsurf agent commands, and Copilot commands sent to the VS Code terminal, run in the editor's integrated terminal, whose parent is the editor or pty host. They are not covered, because an editor terminal cannot be told apart from a human typing in it.
- **Desktop app name overlap.** `claude`/`claude.exe` is also the Claude Desktop process name. Desktop chats do not normally spawn remote-access commands, so the impact is low.
- **`remote_targets` is best effort.** When it cannot be parsed, it shows "not parsed". The full command is in `remote_commands` (first 5 commands, 300 characters each).
- **Command lines are copied into the Risk index.** `remote_commands` is written to every risk event. Common credential forms are redacted (see How it works), but a secret in another form, such as an API token in an environment variable or a custom flag, is copied as typed. Restrict access to the Risk index accordingly, or set the customizations macro to `fields - remote_commands`.
- **Text that looks like a command.** Only git/gh messages and cat/tee heredoc bodies are treated as text. An agent that runs `echo "done; ssh srv01"` or writes "ssh host" into a file with `printf` can produce a false positive.
- **Remote registry and admin shares used by management tools.** These are genuine remote operations and are only counted when an AI agent launched them. See the population results under Validation.

### Validation
Read-only live tests on 2026-10-09 across 4 production ES tenants (labelled A–D). Data volumes are per day.

| Tenant | Endpoint.Processes | Agent parents seen (7d) | Parses (rule + 2 drilldowns) | Rule rows (4h / 7d) | Notes |
|---|---|---|---|---|---|
| A | ~174M/day, all required fields populated | Google Antigravity agent shells (`zsh` running from `~/.gemini/antigravity/`): 2 events on 1 host, child `process_name` reported as "unknown" | yes | 0 / 0 | Regex population test (shells and remote tools, 30 min, ~378k events): 4,229 matches, all genuine remote operations. 4,140 were one management tool's remote-registry `reg delete`/`reg query \\host\hklm\...` calls (138 distinct command lines). 89 were `net use \\host`. Earlier 24h test: recursive `reg ... /s` ~120k events, matched only when a `\\host` target was present. |
| B | ~51k/day | Codex Windows runner `codex-command-runner-<ver>.exe` → `pwsh.exe` (1 event, sandbox account) | yes | 0 / 0 | The agent-child drilldown shows the runner and its PowerShell child. No remote commands. Population test: 0 matches. |
| C | ~156M/day, all required fields populated | `copilot-runtime.exe` (VS Code Copilot agent) on 3 hosts: ~1,670 children in 7d (conhost, pwsh, powershell, git, rg); `copilot-language-server.exe` → conhost on 3 hosts; `codex.exe` → conhost (1 event) | yes | 0 / 0 | No remote commands. Population test (30 min, ~73k events): 3 matches, all an inventory script that PowerShell runs from a remote `\\host\admin$` share. An earlier test caught a local `sc \\localhost config ...`, which is stripped as benign. |
| D | ~210k/day | none | yes | 0 / 0 | Thin endpoint telemetry. Population test: 0 matches. |

Neither the earlier agent list nor the original co-occurrence design recognised the Codex runner or the Copilot runtime in B and C. Both are versioned or differently named processes that do the actual command execution.

Synthetic tests were run in all four tenants through the real macros (Splunk PCRE):
- **Regex corpus: 177/177 cases correct in all four tenants.** The corpus combines the earlier 53 cases, the 99-case adversarial review corpus, and 25 new edge cases.
  - True positives include ssh in Claude Code's `eval '...'` wrapper, `for ...; do ssh $h ...; done`, `if ...; then ssh ...; fi`, multi-line commands, `sudo -u x ssh`, `sudo -E ssh`, `xargs -I{} ssh`, `env A=b ssh`, `VAR=x ssh`, `timeout -k 5 10 ssh`, quoted Windows `ssh.exe`, `pwsh -c`/`-Command` remoting, `icm -cn`, `gwmi -cn`, `etsn host`, `net use z: \\host`, `copy x \\host\admin$\`, `Copy-Item ... \\host\c$`, remote `reg`/`sc`/`schtasks /s`, scp/rsync to `host:`, Impacket, `mstsc /v:`, ssm/gcloud/az shells, `ssh git@github.com.evil-c2.net`, `ssh -J bastion github.com`, `ssh localhost -t "ssh db01"`, `bash <<EOF` heredocs that contain ssh, `git commit -m "$(ssh host)"`, and a real hop hidden behind `git pull git@github.com`.
  - True negatives include `reg query ... /s`, `which ssh`, `command -v ssh`, `grep -c ssh`, `ls /etc/ssh`, `man ssh`, local `scp`/`rsync`, `-ComputerName .`/`localhost`/`$env:COMPUTERNAME`, `Enter-PSSession -ComputerName localhost`, `Enter-PSSession -Id 3`, `wmic /node:localhost`, `sc \\localhost`, `\\fs01\public`, `ssh-keygen`, `ssh -V`, `ssh -G host`, `ssh -Q cipher`, `psexec --help`, git transport, `git push`, a commit message containing "; ssh host", and Claude Code's heredoc commit message with lines that start with "ssh".
- **Full post-tstats pipeline: 9 synthetic agent rows produced the 7 expected detections.**
  - The agents were Claude native with a version-string parent name, an Antigravity shell, OpenCode via node, the Codex runner under a `HOST\CodexSandbox*` account, Copilot runtime, and one user running both Claude and Gemini on the same host.
  - `provider` came from `ai_tool_processes` in every case: Anthropic, Google Gemini, OpenCode, OpenAI and GitHub Copilot. The two-agent user listed both.
  - `gcloud compute ssh` gave cloud_shell only. `ssh -l admin srv04` gave the target `srv04`.
  - `sshpass -p` and `corp/admin:<password>@host` were redacted in `remote_commands`.
  - `risk_score=70` was set only for Impacket. The sandbox account produced host risk only. The heredoc commit-message row was dropped.

Real runs on 2026-10-09 (default 4h window, after this revision) completed with status 200, 0 rows and no errors in all four tenants. Expected production volume is 0/day in all four tenants today. The rule is a low-noise tripwire that becomes relevant as agentic coding tools spread. Tenant C's Copilot agent hosts are where it would fire first.

### Deployment
The package ships with `enable_alerting: false`. Before you enable it:
- Confirm `Endpoint.Processes` carries `parent_process_name` and full command lines for the endpoints that use AI coding agents.
- Run both queries above over the stated windows.
- Allow-list sanctioned agent-driven administration in `ai_sanctioned_entities`.
- Preview the rule over 7 days to measure the daily risk volume after suppression.

The rule is risk-only (`action.risk = 1`, `action.notable = 0`). The AI risk aggregators decide when accumulated risk becomes a notable. Enabling this rule must be one separately approved change.
