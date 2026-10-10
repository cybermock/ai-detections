## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule detects Model Context Protocol (MCP) servers running on endpoints. An MCP server is the bridge that lets an AI assistant or agent (Claude Desktop, Claude Code, Cursor, VS Code Copilot, Codex and similar) read files, query databases, drive a browser or call SaaS and source-control APIs on the user's behalf. An unsanctioned MCP server is a shadow-AI finding and a data-access path that bypasses normal application controls. The rule creates risk on the `user` and on the `src` system. It does not create a notable event.

### Prerequisites

- **`Endpoint.Processes`, accelerated**, with `process_name`, `process` (the full command line), `user` and `dest` populated. Most MCP servers run as `npx`/`node`, `uvx`/`python` or `docker` with the server package on the command line. Without `Processes.process`, the rule only sees MCP servers that run as their own binary (for example `github-mcp-server.exe`).
- `parent_process_name` is context only (the MCP client that started the server). Its fill rate was 13–86% across the validation tenants. Placeholder values such as `unknown` are removed, and the message then says "a parent that was not recorded".
- ES `identity_lookup_expanded`. The rule reads `bunit` for group allowlisting and for `ai_risk_multiplier`. If an identity is missing, group allowlisting does not apply and the multiplier falls back to 1.0.
- Common package `hdsi_ai_rba_common`: `ai_unsanctioned_filter(3)` with the `ai_sanctioned_entities` lookup, and `ai_risk_multiplier` with the `ai_department_sensitivity` lookup.

### How it works

- **Prefilter (tstats).** Endpoint.Processes rows where `process_name` or `process` contains `mcp` or `modelcontextprotocol`, grouped by user, host, process name and full command line. Grouping by the command line means no command line is truncated or lost. The prefilter is broad on purpose. Live data showed that bare `mcp` substrings are common and almost never MCP (see below), so the next step decides.
- **Drop package management and auto-registration.** `npm`/`pnpm`/`yarn`/`bun`/`pip`/`uv`/`poetry`/`conda` install, add, remove, list and similar subcommands, `python -m pip`, and `docker pull|images|ps|logs|rm|build` are dropped, because installing an MCP package is not running it. `<client> mcp config|install ... --source=<extension>` is also dropped. This is an IDE extension registering its MCP server by itself (for example the GitLens extension's `gk mcp config vscode --source=gitlens`). It runs for every user who has the extension, and the user did nothing.
- **Classify (`mcp_role`).** A row is kept only if one of the roles below matches. The first three look at the process name or at an AI client's own `mcp` subcommand. The last two need a **package position**, and they apply **only to package runners and interpreters** (`hdsi_ai_mcp_server_execution_launcher_regex`: node, npx, npm, pnpm, yarn, bun, deno, tsx, uv/uvx, pipx, python, docker, podman), plus a narrow `java -jar`/`dotnet` case. For any other process (browsers, `git`, shells, IDEs, Teams, Notepad, archive tools, installers) the arguments are never read, so URLs, repository names, folders and file names with `mcp` in them do not count.
  - `mcp_server_binary`: the process name itself is an MCP server (`*mcp-server*`, `*mcpserver*`, `*server-mcp*`, `mcp-*`, `*-mcp.exe`, `fastmcp`).
  - `mcp_config_command`: an AI client changes its MCP configuration (`claude mcp add|remove|list|get`, `gk mcp config`, `docker mcp server|catalog|client ...`). This shows adoption but no running server, so it scores 15.
  - `extension_mcp_server`: an AI client's MCP server started by an IDE extension, recognised by `--source=<extension>` (for example GitLens: `gk mcp --host=vscode --source=gitlens`). VS Code starts it when its agent uses tools, so it is real MCP use, but it appears on every workstation with the extension. It scores 15 and is labelled "MCP server started by an IDE extension".
  - `ai_client_mcp_command`: an AI client run by the user as an MCP server or gateway (`claude mcp serve`, `codex mcp-server`, `gk mcp`, `goose mcp`, `docker mcp gateway run`, and similar).
  - `mcp_package` / `launcher_mcp_argument`: a runner with an `mcp` package in one of these positions. The role is `mcp_package` when the token is an official SDK or server name (`@modelcontextprotocol/...`, `fastmcp`, `mcp-server-*`, `*-mcp-server`, `mcp-remote`, `mcp-proxy`). Otherwise it is `launcher_mcp_argument`.
    - a scoped package after whitespace, `=`, `:` or `node_modules\`: `@playwright/mcp@latest`, `@upstash/context7-mcp`, `@modelcontextprotocol/server-filesystem`, or the npx cache path `node_modules\@playwright\mcp\cli.js`
    - the package argument of a runner: `npx -y context7-mcp`, `uvx mcp-server-git`, `uvx fastmcp run`, `uv run --with mcp mcp run`, `pnpm dlx`, `npm exec`, `deno run npm:...`
    - `python -m mcp`, `-m <module>_mcp` or `-m fastmcp`, but not `-m tests.test_mcp`
    - the image of `docker|podman run|create`, found after the run options: `mcp/fetch`, `ghcr.io/github/github-mcp-server`, `*-mcp:tag`. The values of options such as `--network`, `--name`, `-v`, `-e`, `--env-file`, `--add-host` and `-p` are skipped, so `docker run --network mcp-net nginx` does not match.
    - a `.js`/`.ts`/`.py` script whose folder or file name is `*-mcp*`/`mcp-*`/`fastmcp*`, such as `weather-mcp/build/index.js`. Test files (`test_*`, `*.test.*`, `*.spec.*`) and tools under the server's own `node_modules` (`tsc`, `jest`) do not match.
    - `java -jar` or `dotnet` with a `*mcp-server*`/`*mcpserver*`/`*server-mcp*` `.jar`/`.dll` file name (for example a Spring AI or .NET MCP server)

    Shells and general runtimes (`cmd`, `sh`, `bash`, `powershell`) are not runners. In production data their `mcp` tokens were host names, service names and share paths. An MCP client wrapper such as `cmd /c npx -y <server>` is still detected, because the endpoint also logs its `npx`/`node` child process. Flags and config keys such as `--mcp-servers-enabled` or `-c mcp_servers.<name>.command=...` are not package names, and tokens ending in a data or document extension (`.log`, `.dcm`, `.md`, `.zip`, `.msi` and similar) never count.
- **Name and type.** `mcp_server` is the binary, the `@modelcontextprotocol/...` package, the Docker image, the `mcp-server-*` token, the package argument, or `<client> mcp`. A wrapper folder named `mcp-servers` is skipped in favour of the server inside it. `mcp_type` is filesystem, database, source_control, saas, browser, infrastructure, gateway (Docker MCP gateway), web_retrieval, memory, ai_client or unclassified. `data_access=1` for user-run servers of the first seven types.
- **Redact credentials.** `mcp_commands` holds up to five command lines (500 characters each) for the analyst. Before they reach the risk index, token-like values are replaced with `<redacted>`. That covers `Authorization`/`Bearer` headers, `*TOKEN=`/`*API_KEY=`/`*SECRET=`/`*PASSWORD=` assignments, `--token`/`--api-key`/`--header` flag values, URL user:password (up to the last `@` of the authority, so a password that contains `@` is fully removed), and well-known key formats (`sk-`, `ghp_`/`github_pat_`, `xox?-`, `glpat-`, `AKIA`, `AIza`, JWTs). The raw command line stays in the endpoint index and is shown by the drilldown.
- **Clean up risk objects.** `user` is nulled for `unknown`, empty, `SYSTEM`, `root`, `NT AUTHORITY\*`, `LOCAL SERVICE`/`NETWORK SERVICE` and machine accounts (`*$`), so no shared account builds up risk. Such rows give system-only risk. Rows without a usable host are dropped.
- **Aggregate.** One row per `user` + `src`, with up to five MCP servers, the roles, the launchers, the parents and the redacted command lines. `mcp_activity` is "MCP server execution" if any event in the row was a user-run server, otherwise "MCP server started by an IDE extension" or "MCP configuration command (no server run)".
- **Allowlist.** After aggregation, the rule looks up the user's `bunit` in `identity_lookup_expanded` and runs `ai_unsanctioned_filter(user,src,provider)` with `provider="MCP Server"`. When the raw user does not resolve, the common macro also tries the bare name (`DOMAIN\` and `@suffix` removed). Users, hosts, identity groups and the whole organisation can be allowlisted (see "Tuning macros").
- **Score.** `risk_score = min(60, base_score × risk_multiplier)`. `base_score` is the highest per-event base in the row: 40 for a user-run server with data access, 30 for any other user-run server, 15 for an extension-started server, and 15 for configuration commands. `risk_multiplier` comes from `ai_risk_multiplier` (identity `bunit` sensitivity × 1.25 for privileged identities, capped at 2.0). The computed `risk_score` applies to both risk objects. The static `_risk` scores (user 30, system 20) apply only if the risk_score hook removes the field.
- **Schedule and suppression.** Every 15 minutes (`4-59/15`) over `-20m@m` to `-5m@m`. `alert.suppress.fields = user,src` for 86400s, so a long-running or repeatedly relaunched MCP server gives at most one risk event per user and host per day.
- **MITRE ATT&CK.** T1059 (Command and Scripting Interpreter: interpreter-hosted servers give an agent command execution, kill-chain phase `execution`) and T1588.007 (Obtain Capabilities: Artificial Intelligence).

### Tuning macros

| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_mcp_server_execution_launcher_regex` | `"^(node\|npx\|npm\|pnpm\|yarn\|bunx?\|deno\|tsx\|uvx?\|pipx\|py\|pythonw?[0-9.]*\|docker\|podman)(\.exe\|\.cmd)?$"` | Runners whose package-position `mcp` arguments count as evidence. Do not add shells or general runtimes. |
| `hdsi_ai_mcp_server_execution_filter` | `()` | Inline tstats exclusions, e.g. `NOT Processes.dest IN ("ci-runner-*")`. |
| `hdsi_ai_mcp_server_execution_customizations` | `search *` | Post-aggregation tuning, e.g. `search NOT mcp_servers="*approved-internal-mcp*"`; `search is_exec=1` to keep running servers only; `search mcp_activity!="MCP server started by an IDE extension"` to drop GitLens-style extension servers. |
| `hdsi_ai_mcp_server_execution_risk_score` | `search *` | Last pipe. Override or re-cap the computed `risk_score`. |

For sanctioned developer teams or hosts, add an `ai_sanctioned_entities` row with an expiry instead of editing the macros. The provider string is `MCP Server`. Keys:

- `<user>|mcp server` for one user.
- `<host>|*` or `<host>|mcp server` for one host. This is the only per-object key that covers system-only rows (machine accounts, unknown users).
- `<bunit>|mcp server` with `entity_type=group` for an identity business unit. Case does not matter: the filter lowercases the key and the lookup is case-insensitive. The user must resolve in `identity_lookup_expanded`.
- `*|mcp server` (`entity_type=group`, `entity=*`, `scope=global`) to approve MCP use for the whole organisation. This silences the rule completely, including system-only rows.

### Known false positives / Limitations

- **Never match a bare `mcp` substring.** In one day of production data, `*mcp*` on the command line matched about 9,000 process events across 4 tenants, and none were MCP. They came from personal names inside application file paths, random tokens in vendor data-file names, host names and Windows service names that contain the letters "MCP", Windows Update and telemetry correlation vectors (`/cv ...MCP...`), base64 tokens, and an AI coding agent's feature flag (`features.tool_call_mcp_elicitation=false`). Over 7 days, Tenant A had about 62.7k `cmd.exe` and 199 `java.exe` prefilter events with `mcp` in them. Tenant C had 41 `cmd.exe` and 41 `powershell.exe` events. None were MCP, which is why shells are not runners and `java`/`dotnet` need an MCP-server jar or dll name.
- **Developer activity around MCP is not MCP execution.** Browsing MCP docs, cloning an MCP repository, opening an `*-mcp-server` folder in an IDE, unzipping, installing or reading MCP files, and building or testing an MCP server project do not match. Only a runner launching the package, image or script does.
- **Custom servers with no `mcp` in their name are invisible.** `python server.py` or `node build/index.js` does not reveal MCP. A server started through a wrapper `.exe` with no `mcp` in its name, and remote (HTTP/SSE) MCP servers that run off the endpoint, are also invisible to this rule.
- **Docker option parsing is best effort.** The image is the first argument after the known `docker run` options. A value-taking option missing from the list, or a quoted option value that contains spaces, can push the parser onto the wrong token. This was not seen in any tenant. Exclude such hosts with the filter macro.
- **IDE-extension MCP servers score 15.** Expect at most one 15-point event per day for each workstation where an extension such as GitLens starts its MCP server for an AI agent. Drop them with the customizations macro if that is sanctioned.
- **Configuration commands score 15.** `claude mcp add` and a user-run `gk mcp config` show MCP adoption but not a running server. Drop them with `search is_exec=1` if you only want running servers. Extension auto-registration (`mcp config|install ... --source=<extension>`) is ignored completely.
- **Server names are best effort.** `mcp_server` comes from the first matching token. The full redacted command lines are in `mcp_commands`, and the raw ones are in the drilldown.
- **Credential redaction is pattern-based.** A secret in an unusual position, such as a bare positional argument, can still reach `mcp_commands`. If that is not acceptable, remove the field in the customizations macro (`fields - mcp_commands`) and rely on `mcp_servers`.
- **Expected benign hits:** developer workstations using Claude Desktop, Cursor, VS Code agent mode or Claude Code with MCP servers, and vendor tools that ship an MCP server binary. Allowlist sanctioned use instead of removing patterns.

### Validation

Read-only live tests ran on 2026-10-09 against 4 production ES tenants. The rule and its 3 drilldowns parse in all four.

| Tenant | Endpoint.Processes (1h events; cmdline / user / parent fill) | Parses (rule + 3 drilldowns) | Rows: 4h / 24h / 7d | Notes |
|---|---|---|---|---|
| A | ~6.5M; 99.9% / 99.9% / 68.5% | OK | 0 / 0 / 0 | The only MCP-related activity in 7 days was the GitLens extension auto-registering its MCP server (2 events, `--source=gitlens`), which is dropped. About 68k other prefilter events (mostly `cmd.exe`, plus 199 `java.exe`) are all classified as not MCP. |
| B | ~1.8k; 100% / 100% / 13% | OK | 0 / 0 / 0 | Server-only endpoint data, machine accounts only. No prefilter events in 7 days. |
| C | ~6.2M; 93.6% / 42.8% / 18.6% | OK | 0 / 1 / 1 | An MCP server binary for SQL tooling on one development host, launched 414 times in 7 days. `user` and `parent_process_name` are `unknown`, so the risk is system-only, database, score 40, with "a parent that was not recorded". About 195 other prefilter events in 7 days (41 `cmd.exe`, 41 `powershell.exe`, about 85 compiler events, Windows Update and telemetry, 1 `codex.exe` event) are dropped. |
| D | ~8k; 99.9% / 99.9% / 86% | OK | 0 / 0 / 0 | Only Windows Update correlation-vector strings contain `mcp` (4 events in 7 days). They are dropped. |

The 4h figures are today's run of this version (`--max-time 120`, under 7 seconds per tenant, no errors). The 24h and 7d figures come from full runs earlier the same day. This version changes only the argument classification of runners and adds no new source, so the Tenant C binary row is unaffected; its 414 launches were re-counted today. A targeted 7-day check of the shapes added in this version (scoped packages under `node_modules`, `java`/`dotnet`, extension-started servers) found no new rows in any tenant.

A synthetic control ran the full rule pipeline (`makeresults`, 68 command lines) in all four tenants. All four gave the same, expected result: 29 rows kept and 39 dropped. The kept rows covered:

- MCP server binaries
- `node … node_modules\@modelcontextprotocol\server-filesystem`
- `npx -y @playwright/mcp@latest` and its npx-cache child `node … node_modules\@playwright\mcp\cli.js`
- `uvx mcp-server-git` and `uvx fastmcp run`
- `docker run -i --rm mcp/fetch`, `ghcr.io/github/github-mcp-server`, and an image after `--env-file`/`-p`/`--publish-all`
- `docker mcp gateway run`, `claude mcp serve`, `gk mcp`
- `python3 -m mcp_server_sqlite`, `python -m mcp run`, `uv run --with mcp mcp run`
- `node …/weather-mcp/build/index.js`, a quoted script path with spaces, `node …\node_modules\mcp-remote\dist\proxy.js`
- `node npx-cli.js -y @upstash/context7-mcp` (the child of `cmd /c npx`)
- `npx -y mcp-remote … --header Authorization:Bearer …` (bearer redacted)
- `npx -y @modelcontextprotocol/server-postgres postgresql://user:p@ss@host/db` (whole password redacted)
- a `fastmcp` app, `java -jar …mcp-server….jar`, `dotnet …McpServer.dll`
- a machine-account launch (system-only risk)
- `claude mcp add` (configuration, 15) and GitLens `gk mcp --host=vscode --source=gitlens` (extension-started, 15)

The dropped rows included every earlier reviewer counter-example:

- browser URLs to MCP docs and repositories, `git clone` of an MCP repository
- `cmd /c dir …\mcp-servers\`, `Code.exe C:\src\my-mcp-server`
- `node …\github-mcp-server\node_modules\typescript\bin\tsc` (with and without `.js`), `jest` under an MCP project
- `notepad … mcp-server-setup.md`, `7zFM … mcp-proxy-main.zip`, `msiexec /i FastMCP-installer.msi`, a Teams deep link
- `python test_mcp.py`, `python -m tests.test_mcp`, `weather_mcp.test.py`
- `docker run --network mcp-net nginx`, `--name mcp-x`, `--add-host mcp-x:…`, `-v /data/mcp:/data`, `bash -c "ls mcp"` inside a container
- service names, host names (`sqlcmd -S mcp-sql01`, `--host mcp-sql01`), share paths, a bare `mcp` folder, vendor data files under `java`/`python`, telemetry vectors, `--mcp-servers-enabled`, `codex -c mcp_servers.…`, the agent feature flag
- `npm install -g @modelcontextprotocol/…`, `python -m pip install mcp`, GitLens auto-registration

Expected volume at the scheduled cadence, with 24-hour suppression:

- Tenant C: about 1 risk event per day, system-only.
- Tenants A, B and D: 0.

Developer-heavy tenants that use MCP-enabled AI clients should expect about one event per active developer workstation per day (15 points where only an IDE extension's server runs).

### Deployment

The package ships with `enable_alerting: false`. Before enablement:

1. Confirm that the target tenant's `Endpoint.Processes` summaries carry full command lines.
2. Run the search over 7 days and review the `mcp_servers` and `mcp_activity` it lists.
3. Add sanctioned developer users, hosts or bunits to `ai_sanctioned_entities` (provider `MCP Server`).
4. Decide whether configuration-only and extension-started rows (score 15) are wanted. If not, filter them in the customizations macro.
5. Confirm that the risk objects resolve to real users and hosts.

The rule is risk-only. Enabling it and adjusting any aggregator thresholds must be one separately approved change.
