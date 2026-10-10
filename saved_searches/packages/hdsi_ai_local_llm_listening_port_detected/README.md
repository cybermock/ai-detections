## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule detects a local LLM server listening for API requests on a host. Covered servers are Ollama, LM Studio, Jan, GPT4All (including Windows `chat.exe`), KoboldCpp, llama.cpp server and LocalAI, plus vLLM when the process is reported under its own name. A local model server runs AI outside every sanctioned SaaS control: no DLP, no provider contract, no prompt logging. Ollama and most of the others serve an **unauthenticated** HTTP API. A server bound to `0.0.0.0` instead of loopback lets anyone on the network use the model, pull or delete models, or exploit server bugs (for example CVE-2024-37032, Ollama path traversal). The rule creates risk on the host (`dest`, system). It does not create a notable. Process execution of the same tools is covered separately by `hdsi_ai_local_llm_framework_execution`. This rule adds the evidence that the tool is actually *serving*, and shows how widely it is exposed.

### Prerequisites
- **CIM `Endpoint.Ports` (accelerated)** with `dest_port`, `transport`, `state` and `dest` (the bind address) populated. Supported sources:
  - Windows Security Filtering Platform events, through the Splunk Add-on for Windows: 5154 (permitted listen) and 5158 (permitted bind). Both are mapped as `state=listening` and carry `process_id`. A 5158 is a bind, not necessarily a listen, but a TCP bind to one of these fixed ports outside the Windows ephemeral range is almost always a server socket.
  - `netstat` snapshots from the Splunk Add-on for Unix and Linux. These have no `process_id`.
  - Scripted listening-port inventories that map `process_id`.
  - If `Endpoint.Ports` is empty, the rule returns nothing.
- **CIM `Endpoint.Processes` (accelerated)** with `dest`, `process_id` and `process_name`. Each listener is attributed to its owning process from this data model. Without process data, no listener is attributed, and the corroboration gate drops everything. See `..._corroboration` below for the deliberate relaxation. Hex PIDs (Windows 4688) and decimal PIDs (5154, Sysmon, WinHostMon) are normalised.
- **Common package `hdsi_ai_rba_common`:**
  - `ai_process_filter` with the `ai_tool_processes` lookup. Rows with `provider="Local LLM"` define which processes count.
  - `ai_unsanctioned_filter(3)`, the allow-list in `ai_sanctioned_entities`.
- The rule uses no ES identity or asset lookups.
- The previous version used `Network_Traffic` and required a loopback (`127.0.0.1`) address. Firewalls and NetFlow do not see loopback traffic. Across the validation tenants, loopback flows were absent from `Network_Traffic` in A, C and D. In B they appeared only in a small number of firewall-logged flows. That version could never fire. `Network_Traffic` is no longer used.

### How it works
- `tstats` over `Endpoint.Ports` keeps TCP listeners on the LLM port lists. Connection states (`established`, `time-wait`, ...) are excluded, so netstat client rows are dropped. Results are grouped by `host`, bind address (`Ports.dest`) and port, with `values(process_id)`.
- An appended `tstats` over `Endpoint.Processes` looks back `..._process_lookback` (7 days) for processes in `..._process_names`. They are resolved through `ai_process_filter` and kept only when `provider="Local LLM"`. `lms`/`lms.exe` is excluded because Intel Local Management Service uses `LMS.exe`.
- Hosts are normalised to a lowercase short name, so FQDN and short-name sources join. Each listener then gets an `llm_process`:
  - **PID attribution:** the listener's own `process_id` belongs to a Local LLM process on that host. This is the only accepted path for the **generic ports** (5001, 8000, 8080).
  - **Host attribution:** no source reports any PID for that host and port (netstat-only), and a Local LLM process ran on that host within the lookback. This path is accepted only for the **dedicated ports** (11434, 1234, 1337, 4891). A listener whose PID is known but does not resolve to a Local LLM process is dropped, even when an LLM tool ran on the same host. `chat.exe` (GPT4All on Windows) is too generic a name for host attribution and only counts by PID.
- `..._corroboration` drops listeners with no `llm_process`. Port-only matches are not trusted. In the validation tenants, every one of them was a different product (see below).
- `exposure` is `loopback` for `127.*`, `::1` and `::ffff:127.*`, and `unknown` when the bind address is empty or `unknown`. Any other bind address (`0.0.0.0`, `*`, `::`, an interface IP or host name) is `network`. In the validation data, Windows events report every non-loopback bind as the host name, so these count as `network`. Results are aggregated per host, and `exposure_label` reads "reachable from the network", "bound to loopback only" or "bind address not reported (exposure unknown)".
- `ai_unsanctioned_filter(user,dest,provider)` drops sanctioned hosts, users and groups. `user` is the first non-service account that ran the process, and appears for context only. It is not a risk object.
- **Scoring:** the literal `_risk` score is 30 on `dest` (system). `risk_score` is 50 when any listener on the host is network-reachable, otherwise 30 (loopback-only or unknown bind address). There is only one risk object, so the dynamic score applies to it alone.
- MITRE T1588.007 (Obtain Capabilities: Artificial Intelligence). `ai_kill_chain_phase=staging`.
- Runs hourly at :27 over `-65m@m` to `-5m@m`. Suppression is 24 hours on `dest`, so one risk event per host per day.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_local_llm_listening_port_detected_filter` | `()` | Exclusions inside the `Endpoint.Ports` tstats `where` clause, e.g. `NOT host IN ("gpu-lab-*")`. |
| `hdsi_ai_local_llm_listening_port_detected_ports` | `11434,1234,1337,4891` | Dedicated default API ports (Ollama, LM Studio, Jan, GPT4All). Host-level process corroboration is enough. Add a port here if your users run a server on a custom `OLLAMA_HOST` port. |
| `hdsi_ai_local_llm_listening_port_detected_generic_ports` | `5001,8000,8080` | Ports shared with ordinary web apps (KoboldCpp 5001, vLLM 8000, llama.cpp server/LocalAI/Open WebUI 8080). PID attribution is required. Gradio 7860 is not shipped: text-generation-webui runs as `python` and cannot be attributed. |
| `hdsi_ai_local_llm_listening_port_detected_process_names` | Wildcard list (`ollama*`, `lm studio*`, `llama-*`, `gpt4all*`, `chat.exe`, ...) | Pre-filter for the process tstats. The final decision is made by `ai_tool_processes` (`provider="Local LLM"`). Add new runtimes to the common lookup first, then here. |
| `hdsi_ai_local_llm_listening_port_detected_process_lookback` | `-7d@h` | How far back to look for the owning process. A server started earlier that is seen only by netstat is not attributed. |
| `hdsi_ai_local_llm_listening_port_detected_corroboration` | `where isnotnull(llm_process)` | Requires process attribution. Relax it only for hosts with no process telemetry. The macro description shows an example that also accepts network-bound 11434. |
| `hdsi_ai_local_llm_listening_port_detected_customizations` | `search *` | Post-aggregation filter. Fields: `dest`, `user`, `llm_tool`, `llm_process`, `ports`, `bind_addrs`, `exposure`, `exposure_label`, `network_exposed`, `attribution`, `listen_events`. |
| `hdsi_ai_local_llm_listening_port_detected_risk_score` | `search *` | Last pipe. Override `risk_score` (keep it at or below 100), e.g. raise network-exposed servers on servers or in a DMZ. |

To allow a sanctioned AI workstation or GPU server, add a `<host>|local llm` (or `<host>|*`) row to `ai_sanctioned_entities` in the common package.

### Threshold
The rule has no numeric threshold. Any attributed listener counts. Before you enable it, run this query over 7 days to see what is listening on the configured ports and who owns it. It is the rule with the corroboration gate opened:

```spl
| tstats summariesonly=t allow_old_summaries=t count dc(host) as hosts values(Ports.dest) as bind_addr
    from datamodel=Endpoint.Ports
    where Ports.dest_port IN (`hdsi_ai_local_llm_listening_port_detected_ports`,`hdsi_ai_local_llm_listening_port_detected_generic_ports`)
      Ports.transport IN ("tcp","tcp6")
      NOT Ports.state IN ("established","time-wait","close-wait","syn-sent","syn-recv","fin-wait-1","fin-wait-2","last-ack","closing")
    by Ports.dest_port sourcetype
| sort - hosts
```
Pick one host per port. Resolve its listener PID to a process name with the "View local LLM port listeners" drilldown, then the Endpoint.Processes data. That tells you whether the port belongs to a local LLM server or to something else. Only the attributed rows reach risk.

### Known false positives / Limitations
- **Port-only matches are almost never LLMs.** Over 7 days, port-only matching would have flagged 14 hosts in Tenant A and 46 in Tenant C. None of them were LLM servers:
  - A micro-segmentation agent opened loopback listeners on 11434, 1337, 4891 and 43411.
  - A document-imaging OCR service listened on 127.0.0.1:11434.
  - Middleware servers listened on `*:1234`.
  - Ordinary web apps used 5001, 7860, 8000 and 8080.
  
  Where the listener reports a PID (Windows 5154/5158, scripted inventories), PID attribution drops all of these, even on a host that also runs an LLM tool. Do not remove the corroboration gate tenant-wide.
- **Host attribution can mislabel a listener.** On a netstat-only host (no PID from any source for that port) that also ran an LLM runtime within the lookback, a non-LLM listener on a *dedicated* port is attributed to that runtime. In Tenant C, 11 hosts had netstat-only `*:1234` middleware listeners; none ran an LLM runtime, so none fired. Generic ports always need PID attribution.
- **Long-running servers seen only by netstat.** If the LLM process started before the lookback, it is not attributed. Windows 5154 fires when the socket starts listening, so it is attributed whenever process creation is logged.
- **Custom ports.** A server moved off its default port (`OLLAMA_HOST=0.0.0.0:9999`) is missed. Add the port to `..._ports` if this is common in your fleet.
- **Interpreter-launched servers.** text-generation-webui, and vLLM or Open WebUI when the EDR reports the interpreter (`python`, `python3`) as the process name, cannot be attributed. vLLM is matched only when the process name is `vllm`.
- **Containers.** An LLM server inside Docker or WSL shows the container runtime as the listener (`com.docker.backend`, `wslrelay`, `vpnkit`). It is not attributed.
- **Endpoint coverage.** macOS and Linux developer laptops rarely send `Endpoint.Ports`. This rule mainly sees Windows hosts with 5154 auditing and Linux servers with the netstat input.
- **`lms` excluded.** LM Studio's CLI shares the name with Intel's `LMS.exe`, which was present on 225 hosts in one tenant. LM Studio is still matched through `LM Studio.exe`/`lmstudio`.

### Validation
Read-only live tests on 2026-10-09 across 4 production ES tenants (labelled A–D).

| Tenant | Endpoint.Ports | Local LLM processes (30d) | Parses | Rule rows (4h / 7d) | Port-only hosts that would have fired (7d) | Notes |
|---|---|---|---|---|---|---|
| A | Windows Filtering Platform, ~42M/day, with PID; ~99.7% are 5158 (bind) and ~0.3% 5154 (listen); 5 listening events on the LLM ports in 24h | none | yes | 0 / 0 | 14 | The only 11434 listener was an OCR imaging service (PID-verified). The firewall saw ~500k events/day on 11434 from 1,440 sources (ephemeral-port collisions and scanning). This is why `Network_Traffic` was dropped. |
| B | ~0 (one EDR host) | none | yes | 0 / 0 | 0 | No listening-port telemetry. The only loopback-address flows were in firewall logs. |
| C | Windows 5154 (5158 nearly absent), netstat and a scripted inventory, ~64M/day | none (`LMS.exe` on 225 hosts was Intel LMS, not LM Studio) | yes | 0 / 0 | 46 | Loopback listeners on 11434/1337/4891 belonged to a micro-segmentation agent (PID-verified). Middleware listened on `*:1234`. |
| D | Windows Security with no port or state (`dest_port=0`) | none | yes | 0 / 0 | 0 | Ports data is unusable for this rule. |

- **Prior version:** `Network_Traffic` with a loopback requirement returned 0 rows in all tenants, and could not have returned anything. Its traffic drilldown ran an unfiltered `tstats` over all of `Network_Traffic` (more than 300 s on Tenant A). It is replaced by host-scoped `Endpoint.Ports` and `Endpoint.Processes` drilldowns, each a few seconds.
- **Synthetic positive test:** makeresults port and process rows fed through the full post-tstats pipeline gave the expected 3 detections:
  - Ollama on `0.0.0.0:11434`, hex PID `0x1a2b` matched to decimal PID 6699 → `network`, `risk_score=50`, PID attribution.
  - LM Studio on netstat `*:1234` with no PID → host attribution, 50.
  - Ollama on `127.0.0.1:11434` run by SYSTEM → loopback, 30, no `user`.
  
  The test correctly dropped a loopback 4891 listener owned by a non-LLM PID, and a no-PID 8080 listener on a host that ran Ollama.
- **Adversarial re-test (same day):** a review found that host attribution also applied to listeners whose PID was known but was not an LLM process. A host running Ollama on `127.0.0.1:11434` plus a non-LLM PID on `<hostname>:1234` was reported as "reachable from the network", score 50. After the fix, a 9-host synthetic set gives exactly 5 detections: that host is now loopback-only, port 11434, score 30, PID attribution. A netstat `*:1234` row is dropped when another source reports a non-LLM PID for the same port. GPT4All `chat.exe` on `0.0.0.0:4891` is attributed by PID (tool `gpt4all`), but not by host. An `unknown` bind address is labelled "bind address not reported" at score 30. Real 7-day runs still return 0 rows in A–D, and every search and drilldown parses in all four tenants.

Expected production volume is 0 risk events/day in all four tenants today. At most one event per host per day when a local LLM server appears.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:
- Confirm `Endpoint.Ports` carries real listening ports (`dest_port` other than 0, and `state`), and that `Endpoint.Processes` covers the same hosts with `process_id`.
- On Windows, enable "Audit Filtering Platform Connection" (success). That subcategory produces 5154 (listen), 5156 (connection) and 5158 (bind). Keep 5154 and 5158 for this rule; 5158 is by far the highest-volume of the two in some fleets, so filter it at the forwarder to the configured ports if volume matters.
- Run the Threshold query and confirm the owners of any listeners on the dedicated ports.
- Allow-list sanctioned AI hosts in `ai_sanctioned_entities`.

The rule is risk-only (`action.risk = 1`, `action.notable = 0`). The AI risk aggregators decide when accumulated risk becomes a notable. Enabling this rule must be one separately approved change.

The stanza keeps its original `Network - ...` name so that existing deployments update in place rather than creating a second correlation search. The data is Endpoint, so `security_domain` is now `endpoint`.
