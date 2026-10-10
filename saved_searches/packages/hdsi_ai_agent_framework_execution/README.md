## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule detects endpoints launching an autonomous AI agent or agent-orchestration framework, such as CrewAI, AutoGen Studio, LangGraph or LangServe, OpenHands (formerly OpenDevin), SWE-agent, MetaGPT, GPT-Engineer or AutoGPT. These frameworks let an LLM plan and run multi-step tasks. Many of them run shell commands, edit files and call external APIs without a human approving each step, so an unsanctioned one is both a shadow-AI finding and a possible execution channel. The rule creates risk on the `user` (40) and on the `src` system (30). It does not create a notable event.

### Prerequisites

- **`Endpoint.Processes`, accelerated**, with `process_name`, `process` (the full command line), `user` and `dest` populated. The command line does most of the work. Without `Processes.process`, the rule only sees framework CLIs that the EDR reports under their own name (mostly Windows `crewai.exe`-style launchers). Linux and macOS console scripts usually show up as `python3`, so the rule misses them.
- `parent_process_name` only adds context and is optional. Its fill rate was 12–86% across the validation tenants.
- Common package `hdsi_ai_rba_common`, which provides `ai_unsanctioned_filter(3)` and the `ai_sanctioned_entities` lookup.
- No ES asset or identity lookups are required.

### How it works

- **Prefilter (tstats).** A process matches if `process_name` is a known framework CLI (`hdsi_ai_agent_framework_execution_cli_names`). It also matches if `process_name` is an interpreter or launcher (python, py, uv/uvx, pipx, poetry, docker, podman) and the command line contains a framework-specific pattern (`hdsi_ai_agent_framework_execution_cmdline_patterns`). Results are grouped by user, host, process name and command line.
- **Drop package management and tests.** The rule drops `pip`/`uv`/`poetry`/`conda`/`npm` install, add, sync and similar subcommands, `python -m pip|venv|pytest|unittest`, and `docker pull|images|ps|logs|rm`. Installing or testing a framework is not running an agent.
- **Classify.** Each command maps to a `provider` (CrewAI, AutoGen, LangGraph, LangChain, OpenHands, SWE-agent, MetaGPT, GPT-Engineer, AutoGPT, Devika, BabyAGI, SuperAGI, AgentGPT, Smol Developer, smolagents). Commands that match no framework are dropped. `agent_class` is `autonomous_agent` for frameworks that act on the host themselves and `agent_orchestration` for CrewAI, AutoGen, LangGraph and LangChain.
- **Clean up risk objects.** `user` is nulled for `unknown`, empty, `SYSTEM`, `root`, `NT AUTHORITY\*`, `LOCAL SERVICE`/`NETWORK SERVICE` and machine accounts (`*$`), so no shared account builds up risk. In that case only the system gets risk. Rows without a usable host are dropped.
- **Allowlist.** `ai_unsanctioned_filter(user,src,provider)` drops sanctioned users, hosts and groups using `ai_sanctioned_entities`.
- **Aggregate and score.** Rows are aggregated per `user` + `src` and carry static scores: user 40, system 30. `alert.suppress.fields = user,src` with a 24-hour suppression period, so there is at most one risk event per user and host per day.
- **Schedule.** The rule runs every 15 minutes (`2-59/15`) over `-20m@m` to `-5m@m`.
- **MITRE ATT&CK.** T1059 / T1059.006 (Python), plus T1588.007 (Obtain Capabilities: Artificial Intelligence).

### Tuning macros

| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_agent_framework_execution_cli_names` | quoted list of framework CLI names (+ `.exe`) | Exact `process_name` matches. Add new framework CLIs here. |
| `hdsi_ai_agent_framework_execution_launchers` | `"python*","py.exe","uv","uvx","pipx","poetry","docker","podman"`… | Processes whose command line is inspected. |
| `hdsi_ai_agent_framework_execution_cmdline_patterns` | framework-specific `*pattern*` list | Command-line wildcards for launchers. Keep them specific. |
| `hdsi_ai_agent_framework_execution_filter` | `()` | Inline tstats exclusions, e.g. `NOT Processes.dest IN ("ci-runner-*")`. |
| `hdsi_ai_agent_framework_execution_customizations` | `search *` | Post-aggregation tuning, e.g. `search NOT provider="LangGraph"`. |
| `hdsi_ai_agent_framework_execution_risk_score` | `search *` | Set a numeric `risk_score` (`min(100, …)`) to override both static scores for a row. |

For a sanctioned developer team or host, prefer an `ai_sanctioned_entities` entry (`user|provider`, `host|*` or `group|provider`, with an expiry) over editing the macros.

### Known false positives / Limitations

- **Do not widen the command-line patterns to bare words.** In live data, wildcard matches for `*gpte*`, `*dify*` and `*n8n*` hit random temp-directory names (`csc.exe` compiles), VBS and PowerShell script names, and Windows Update arguments. The process name `Interpreter.exe` also exists in production for an unrelated product. For these reasons `devika` only matches `devika.py`, and LangChain only matches `langchain serve` and `langserve`. Open Interpreter, Goose and Dify are not covered.
- **Library-only use is invisible.** If a user runs `python my_agent.py` and the script imports `crewai` or `langgraph`, no framework name appears on the command line unless the project path contains it. Network-side rules (the AI provider DNS and web detections) cover that usage.
- **Long-running agent servers fire once per start.** Examples are `langgraph dev`, an OpenHands container or AutoGen Studio. Child processes spawned by an agent are covered by `hdsi_ai_agent_autonomous_action_detection` and by the "child processes spawned by agent framework CLIs" drilldown. That drilldown pivots only on CLI-named parents: python-hosted agents show `python` as the parent, which live data showed is far too common (Oracle, Spyder and monitoring scripts) to pivot on.
- **Expected benign hits:** developers evaluating frameworks, CI runners building agent projects, and data-science notebook hosts. Allowlist them with `ai_sanctioned_entities` or the filter macro instead of removing frameworks.
- **Pre-v1.1 versions** matched only `process_name` against names such as `devika` or `autogen` that no real CLI uses. They never matched Python-launched frameworks, and they emitted risk on the literal user `unknown`.

### Validation

Read-only live tests ran on 2026-10-09 against 4 production ES tenants.

| Tenant | Endpoint.Processes (1h events, cmdline / user fill) | Parses (rule + 3 drilldowns) | Rule rows: 24h / 7d (runtime 7d) | Notes |
|---|---|---|---|---|
| A | ~6.4M, 99.9% / 99.9% | OK | 0 / 0 (38s) | ~20k `python.exe`/day on ~145 hosts, all script-based. No agent frameworks. `Interpreter.exe` exists here (unrelated product). |
| B | ~1.8k, 100% / 100% (machine accounts only) | OK | 0 / 0 (1s) | Server-only endpoint data. No interpreters seen. |
| C | ~6.3M, 93.5% / 43.4% | OK | 0 / 0 (17s) | ~273k `python.exe`/day on ~268 hosts. Most `user` values are machine accounts or unknown, so system-only risk is expected here. Bare-word patterns produced FPs (see above). |
| D | ~8.3k, 99.9% / 99.9% | OK | 0 / 0 (8s) | Small server fleet. No interpreters seen. |

A synthetic positive control ran the full post-tstats pipeline (`makeresults` with 14 command lines) on Tenant A. It produced exactly the 7 expected detections:

- `crewai.exe run`
- python3-launched `openhands`
- `docker run …all-hands-ai/openhands`
- `autogenstudio ui`
- `uvx crewai create`
- `langgraph dev` as SYSTEM (system-only risk)
- `gpte` as a machine account (system-only risk)

It correctly dropped 7 non-detections: `pip install`, `uv pip install`, `docker pull`, a `devika` username path, `python -m pytest`, a project path containing `langchain`, and an unknown host.

Expected volume at the scheduled cadence is 0 risk events per day in all four tenants today. Where developers adopt agent frameworks, expect at most one event per user and host per day.

### Deployment

The package ships with `enable_alerting: false`. Before enablement:

1. Confirm that the target tenant's `Endpoint.Processes` summaries carry full command lines.
2. Run the search over 7 days to list existing framework users and hosts, and add the sanctioned ones to `ai_sanctioned_entities`.
3. Confirm that the risk objects resolve to real users and hosts.

The rule is risk-only. Enabling it and adjusting any aggregator thresholds must be one separately approved change.
