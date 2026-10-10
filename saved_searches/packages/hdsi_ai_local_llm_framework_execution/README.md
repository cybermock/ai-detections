## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule detects endpoints running a local large language model runtime: Ollama, LM Studio (app and `lms` CLI), llama.cpp (`llama-server`, `llama-cli`, `llama-run`), llamafile, Jan, GPT4All, KoboldCpp, LocalAI, vLLM, Hugging Face Text Generation Inference, Apple MLX LM and Open WebUI. Local runtimes bypass every web, CASB and AI-gateway control. Prompts and data never leave the host, the models are unvetted downloads, and in server mode the runtime exposes an unauthenticated inference API on the network. The rule writes risk on the user (when the process has an attributable human account) and on the system. It does not create a notable.

MITRE ATT&CK: T1588.007 (Obtain Capabilities: Artificial Intelligence).

### Prerequisites

- **`Endpoint.Processes`, accelerated.** The rule uses `summariesonly=t`, so an unaccelerated model returns nothing. Fields used are `process_name`, `process`, `process_path`, `parent_process_name`, `user` and `dest`.
  - `process_name` and `dest` are required.
  - To accept the generic names `lms.exe`, `chat.exe` and `jan`, either `process_path` or `process` (the command line) must show that tool's install folder. One of the two is enough. If a source records only the bare image name (for example `WinHostMon` inventory, where `process` is just `LMS.exe` and `process_path` is empty), those three tools are not detected.
  - `process` (the command line) is required to find Python-hosted runtimes: vLLM (`vllm serve`, `vllm.entrypoints`), MLX LM (`mlx_lm.server`), Open WebUI (`open-webui serve`) and llama-cpp-python (`llama_cpp.server`). The command-line match is accepted only when the process itself is a Python interpreter, `uvicorn`/`gunicorn` or the runtime's own launcher, so `grep`, `pgrep -f` or an editor that mentions these strings is ignored.
  - `user` is optional. The rule emits system risk only when the user is missing or `unknown`, a Windows service account (`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`), a machine account (`HOST$`), a shared Linux or cloud account (`root`, `nobody`, `daemon`, `ec2-user`, `ubuntu`, `azureuser`, `administrator`), a runtime service user (`ollama`, `vllm`, `localai`) or matches `svc_*`/`*_svc`. See `hdsi_ai_local_llm_framework_execution_nonhuman_accounts`.
- **Coverage must include workstations.** Local LLMs run on developer laptops and GPU workstations. A tenant that only forwards process events from servers is blind to this activity.
- **ES `identity_lookup_expanded`** feeds `ai_risk_multiplier` (identity `bunit` sensitivity, and the privileged/critical flag).
- **Common package `hdsi_ai_rba_common`:** `ai_process_filter` (lookup `ai_tool_processes`, rows with `usage_type=local_llm`), `ai_unsanctioned_filter(3)` (lookup `ai_sanctioned_entities`) and `ai_risk_multiplier` (lookup `ai_department_sensitivity`).

### How it works

- `tstats` on `Endpoint.Processes` selects known runtime executable names (case-insensitive, including `ollama app.exe`, `ollama_llama_server.exe`, `LM Studio.exe` and `koboldcpp*` builds) **or** command lines of the Python-hosted servers. Then it groups by `user`, `dest` and `process_name`. `fillnull_value="unknown"` keeps rows whose `user` is null.
- Aliases and command-line matches are normalised to a canonical tool key, for example `ollama app.exe` to `ollama` and `python -m vllm.entrypoints...` to `vllm`.
- Command-line hits are normalised only when the process is an interpreter or the runtime launcher (`python*`, `py`, `uvicorn`, `gunicorn`, `vllm`, `mlx_lm.*`, `open-webui`). Any other process whose command line mentions a runtime keeps its own name, finds no match in `ai_tool_processes`, and is dropped.
- `hdsi_ai_local_llm_framework_execution_ambiguous_name_check` drops `lms`, `chat` and `jan` unless the path **or** the command line proves that specific tool:
  - `lms`: `.lmstudio`, or an `LM Studio`/`lm-studio` folder.
  - `chat.exe`: a `gpt4all` or `nomic.ai` folder.
  - `jan`: the Jan install location (`Programs\Jan`, `AppData\Local\Jan`, `Program Files\Jan`, `Jan.app`, `/opt/Jan`, a Jan AppImage, `/usr/bin/jan`). A user profile or folder that is merely named `jan` does not count.
- `ai_process_filter` resolves the key against `ai_tool_processes`, and the rule keeps rows with `usage_type=local_llm` and `enabled=1`.
- `llm_mode=server` is set when the runtime is a server (Ollama always runs its API, plus llama-server, vLLM, TGI, LocalAI, Open WebUI and MLX server) or the command line has `serve`, `server`, `--host`, `--listen` or `--port`. Otherwise it is `interactive`.
- `hdsi_ai_local_llm_framework_execution_nonhuman_accounts` strips any `DOMAIN\` prefix and maps service, machine and shared accounts to an empty `user`. The official Ollama Linux installer runs `ollama serve` as the `ollama` user, and many servers run runtimes as `root`. Without this step one shared identity would collect risk from every GPU host.
- Results are rolled up to one row per `user` + `src`. Rows the sanctioned-entity allowlist covers are removed.
- **Scoring:** `risk_score = min(60, round(base x risk_multiplier))`, with base 30 for server mode and 20 for interactive use. `risk_multiplier` comes from `ai_risk_multiplier` (1.0 to 2.0). The SPL `risk_score` applies to both risk objects. The literal `_risk` scores (user 20, system 15) are the fallback if the field is removed.
- Suppression is 24 hours on `user,src`. An always-on runtime such as `ollama serve` therefore yields at most one risk event per user and host per day. The rule runs hourly (`17 * * * *`, `-65m@m` to `-5m@m`).

### Tuning macros

| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_local_llm_framework_execution_filter` | `()` | Exclusions inside the `tstats` where clause (`Processes.*` names), e.g. `NOT Processes.dest IN ("gpu-lab-*")` for an approved ML lab. |
| `hdsi_ai_local_llm_framework_execution_ambiguous_name_check` | `where NOT ((lms AND NOT lm-studio path) OR (chat AND NOT gpt4all path) OR (jan AND NOT Jan install path))` on `ctx_lc` (path + command line) | Per-tool corroboration for generic executable names. Extend a tool's pattern if your build deploys it to another path. Do not remove the check: `lms.exe` is Intel's Local Manageability Service on many corporate Windows images. |
| `hdsi_ai_local_llm_framework_execution_nonhuman_accounts` | `eval user=if(<service/shared account regex> OR user ends with $, "unknown", user)` | Accounts that must never carry user risk. Add your service-account naming convention (for example `^svc-`) to the regex. Matching rows still give system risk. |
| `hdsi_ai_local_llm_framework_execution_customizations` | `search *` | Post-aggregation filtering on `user`, `src`, `tools`, `llm_mode`, `process_path`, `process`. |
| `hdsi_ai_local_llm_framework_execution_risk_score` | `search *` | Last pipe. Override `risk_score`, e.g. `eval risk_score=10` in a research tenant, or `eval risk_score=if(llm_mode="server",50,risk_score)` where exposed inference APIs are a policy violation. |

Approved users, hosts or groups belong in `ai_sanctioned_entities` (provider `Local LLM`, or `*`), not in the filter macro. Allowlist entries expire.

### Threshold

None. Any execution of an enabled `local_llm` tool is reportable. Per-day volume is bounded by the 24-hour suppression on `user,src`.

### Known false positives / Limitations

- **Intel LMS (`LMS.exe`).** In validation this was the only match in 7 days across all four tenants: 225 hosts in Tenant C, about 66k `WinHostMon` inventory events per day, with no user and no path. The `process` field holds only the bare name `LMS.exe`. The pre-1.1 rule would have written about 5,400 `unknown`-user risk events per day. The ambiguous-name check now drops it, and the common lookup should stop treating `lms.exe` as a standalone key (see the common package).
- **Expected true positives that are sanctioned:** data-science or ML-engineering workstations and GPU servers. Add them to `ai_sanctioned_entities`, not the filter, so the exemption is reviewed and expires.
- **Blind spots:**
  - Renamed binaries.
  - Runtimes embedded in other applications: an Electron app that bundles llama.cpp, or a Python notebook that calls `transformers` directly.
  - Containers (`docker run ollama/ollama`), unless container process events reach `Endpoint.Processes`.
  - Python-hosted servers on sources without a command line, or launched through a wrapper that is not an interpreter (the Python child is still caught when its own event is logged).
  - `lms server start` from a source that logs only the command line, with no path. The bare `lms` name cannot be told apart from Intel LMS.
  - A runtime started under a personal account on a host where it normally runs as a service account gets user risk. One started under an account the regex treats as shared gets system risk only.
  - Pair this rule with `hdsi_ai_local_llm_listening_port_detected` (ports 11434/1234 etc.) and `hdsi_ai_llm_model_file_download` (model registry pulls).
- **DNS shows interest the process data cannot see.** In Tenant B, DNS showed the Ollama site queried by about 160 sources, and the Ollama model registry and LM Studio model endpoints by 2–3 sources in 7 days. Endpoint process events there come from a handful of servers only, so this rule cannot see those workstations. Closing that gap is an onboarding task, not a rule change.
- `original_file_name` is not used. It was absent or `unknown` in all four tenants.

### Validation

Read-only live tests, 2026-10-09, against 4 production ES tenants. "Before" is the pre-1.1 rule, "After" is this version. The windows are the last 4 hours for the scheduled-window runs and 7 days for the wide run.

| Tenant | Endpoint.Processes | Parses (search + 2 drilldowns) | Before (4h) | After (4h / 7d) | Notes |
|---|---|---|---|---|---|
| A | ~174M/day, Windows 4688 with path and command line | OK | 0 rows | 0 / 0 | No local LLM executables or Python-hosted servers in 7 days. DNS shows a few hosts visiting the Ollama site. |
| B | ~51k/day, servers only | OK | 0 rows | 0 / 0 | No workstation process coverage. DNS shows broad Ollama/LM Studio interest the rule cannot see. |
| C | ~156M/day, about half `WinHostMon` inventory (bare image name, no path or user) | OK | **225 rows, all Intel `LMS.exe`, user `unknown`** | 0 / 0 | The only 7-day pre-filter match is `LMS.exe` (225 hosts, ~480k events), and all of it is now dropped. No real local LLM execution. |
| D | ~210k/day | OK | 0 rows | 0 / 0 | No matching activity. |

No tenant had a command-line hit from a non-runtime process in 7 days.

**Positive-path test.** 26 synthetic process rows were run through the full rendered pipeline on all four tenants. Every tenant returned exactly the expected 15 rows.

Kept with user risk:
- LM Studio `lms.exe` under `.lmstudio` (server mode).
- `lms.exe` under `...\Programs\LM Studio\...` (folder name with a space).
- `lms.exe` with the path only (no command line).
- GPT4All `chat.exe` with the command line only (no path).
- GPT4All `chat.exe` under `gpt4all`.
- `python.exe -m vllm.entrypoints...` and `python3.11 .../vllm serve`.
- `ollama app.exe` + `ollama.exe serve`, merged into one row.
- `koboldcpp_cu12.exe`.

Kept with system risk only (no user risk object):
- `ollama serve` as `SYSTEM`, `root`, `ollama`, `ec2-user` and `svc_ml`.
- `Jan.exe` as a machine account.

Dropped:
- Intel `LMS.exe`, with and without a path.
- `chat.exe` outside a GPT4All folder, and `chat.exe` under `...\economics\`.
- `chat.exe` and `lms.exe` in a user folder named `jan`.
- `jan` with no path.
- `grep -r vllm serve` and `pgrep -f llama_cpp.server`.
- A row with no `dest`.

Command-line wildcards containing spaces (e.g. `"*vllm serve*"`) were confirmed to match in accelerated `tstats` on Tenants A, C and D.

### Deployment

The package ships with `enable_alerting: false`. Before you enable it, confirm that `Endpoint.Processes` covers workstations, not only servers, and that `process_path` or `process` is populated. Then run the search over 7 days and add sanctioned ML hosts and users to `ai_sanctioned_entities`. This rule is risk-only. Enable it as one separately approved change.
