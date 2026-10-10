## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule detects a user or host fetching LLM model weights from Hugging Face, ModelScope or the Ollama registry, using Web (proxy or firewall URL logs) and DNS evidence; visits to the hub web sites never count. A downloaded model runs outside every sanctioned AI control (no DLP, no provider contract, no prompt logging), and pickle-based `.bin`/`.pt` checkpoints can carry code. The rule creates risk on the `user` and on the host (`src`, system), whichever is known, and no notable. Running the model is covered by `hdsi_ai_local_llm_framework_execution` and `hdsi_ai_local_llm_listening_port_detected`.

### Prerequisites
At least one of these data models, accelerated:
- **CIM `Web`** from an egress proxy, SSE/CASB or URL-filtering firewall. Fields used: `url_domain` or `site` (either is enough), `url`, `user`, `src`, `bytes_in`, `sourcetype`.
  - Host-only URL logs (no TLS decryption) still give the model-hub-client and model-CDN evidence. The weight-file evidence needs the URL path. The large-download evidence needs `bytes_in`. Firewall URL logs have no bytes.
  - SSE products that log an app name in `site` ("Hugging Face") with no hostname contribute only through `bytes_in`.
  - Inbound WAF, load-balancer and web-server logs in `Web` carry internet scanners that send model-hub `Host` headers. The untrusted-source rule drops them (see How it works).
- **CIM `Network_Resolution`** with `DNS.query` and `DNS.src` from client-facing DNS logs (resolver query logs, a DNS security service, or network capture). Trailing-dot names (`cas-server.xethub.hf.co.`) are handled. `src` must be the client. Resolvers and forwarders that appear as the client are dropped by the shared-source guard.
- **ES lookups:** `identity_lookup_expanded` (user `bunit`) and `asset_lookup_by_str` (host `bunit`). Both feed the group key of the allow-list only. The risk multiplier (`ai_risk_multiplier`) reads the identity of `user` only, so host-only rows always score with multiplier 1.0, whatever the asset `bunit`.
- **Common package `hdsi_ai_rba_common`:**
  - `ai_domains_filter` with `ai_provider_domains` and `ai_provider_apps`. Hugging Face and ModelScope resolve to provider `Model Registry` (`usage_type=model_registry`). Ollama, including its R2 blob bucket, resolves to `Local LLM` (`usage_type=local_llm`). Only these two usage types are kept, so the Hugging Face inference hosts (`router.huggingface.co`, `api-inference.huggingface.co`, `usage_type=api`) are not counted.
  - `ai_unsanctioned_filter(3)` with `ai_sanctioned_entities`, the allow-list.
  - `ai_risk_multiplier` with `ai_department_sensitivity`.
  - The `ai_detection_config` row `model_download_mb` is not read. The threshold is the package macro `..._min_mb`.

### How it works
- **Shared-source guard (outer search):** the first `tstats` finds DNS clients that resolved at least `..._shared_src_names` distinct names in the day. All their rows (DNS and Web) are dropped later. It is the outer search, not a subsearch, so it always completes: on the largest validation tenant it is most of the 107 s run.
- **Web branch (appended, `maxtime=600`):** `tstats` over `Web`, pre-filtered inline by `..._web_scope` (model hub hosts in `url_domain` or `site`, plus SSE app names) and `..._filter`. `fillnull_value="unknown"` keeps rows that fill only one of `url_domain`/`site`. Inside the subsearch the URL path is tested against `..._weight_file_pattern` and the rows are folded to one per `sourcetype`, `user`, `src` and host, so the subsearch row limit is never reached by URL variety. `ai_domain` is `url_domain`, or `site` when no domain is logged.
- **DNS branch (appended, `maxtime=600`):** `tstats` over `Network_Resolution`, pre-filtered by `..._dns_scope`: only names that serve weights (Hugging Face LFS and Xet storage, ModelScope LFS, the Ollama registry and the Ollama blob bucket on Cloudflare R2). Logs that record both the query and the response are counted once (`max(count)` per message type).
- If an appended branch is cut short, the rule misses evidence for that day. It never marks the wrong host, because the guard has already run.
- **Resolution:** the Ollama blob bucket is mapped to `registry.ollama.ai`. `ai_domains_filter` then resolves and normalises every name, and rows that are not `model_registry` or `local_llm` are dropped.
- **Identity:**
  - Placeholder users (`unknown`, `-`, IP addresses) become null.
  - A `src` that matches `..._untrusted_src` (public IPv4 by default) or `..._unstable_src` (IPv6, and `192.168.0.0/16` from roaming DNS-security agents by default) is never a risk object, and a row with such a `src` and no user is dropped.
  - A DNS row with no user is attributed to a user only when exactly one user appears in the model-hub Web rows from the same host that day, and the DNS lookups fall within one hour of that user's first and last model-hub Web request. Otherwise the row stays host-only.
- **Evidence per user or host and provider** (one row per `risk_entity` = user, else host):
  - **Model hub client** (`tool_events`): any request or lookup for `..._tool_hosts`. These are the Hugging Face Xet client hosts (`cas-server`/`transfer.xethub*.hf.co`, used by `huggingface_hub`, `transformers`, LM Studio and similar) and the Ollama registry. Browsers do not use them. The same hosts carry uploads (`huggingface_hub` uploads and `push_to_hub`, `ollama push`), and DNS cannot tell the direction (see Limitations).
  - **Weight-file URL** (`weight_events`): a Web URL path that matches `..._weight_file_pattern`: a weight file (`.gguf`, `.safetensors`, `.bin`, `.pt`, `.onnx`, ...) fetched through a download endpoint (Hugging Face or ModelScope `/resolve/<revision>/<file>`, or a ModelScope API `FilePath=` parameter), or an Ollama blob pull (`/v2/<name>/blobs/sha256:<digest>`, and `/v2/blobs/sha256/<xx>/<digest>/data` on the R2 bucket). Not counted: the Hugging Face file viewer (`/blob/`, `/tree/`, `/raw/`), config, tokenizer and README files, dataset repositories (any path with `/datasets/`), and training-state files (`training_args`, `optimizer`, `scheduler`, `scaler`, `rng_state*`). `model_file` is the file name, or `sha256:<first 12 hex>` for an Ollama blob.
  - **Large download:** at least `..._min_mb` (500 MB) of `bytes_in` from model hub hosts in the day.
  - **Bulk model-CDN fetch** (`cdn_events`): at least `..._min_cdn_events` (25) requests or lookups for the storage CDNs (`cdn-lfs*`, `cas-bridge.xethub*`, `*.cdn.hf.co`). Fewer than that is a model card's embedded images.
  - A row needs at least one of the four.
- **Approvals:** the identity and asset `bunit` is looked up. `ai_unsanctioned_filter(user,src,provider)` removes approved users, hosts, groups and organisation-wide providers. Providers are then folded into one row per `risk_entity`.
- **One system risk per host:** a host can appear in more than one row, for example as its own host-only row and in a user row. It is emitted as the `src` risk object only once a day: on its host-only row if there is one, otherwise on the first user row. The other rows keep it in `src_display` and `src_list`.
- **Scoring:** the base score is 40 for a large download, 30 for a model hub client or a weight-file URL, and 20 for a bulk CDN fetch only. It is +10 when two or more evidence types agree. `risk_score = min(60, max(10, round(base x risk_multiplier)))`. `risk_multiplier` comes from `ai_risk_multiplier`: the user's identity `bunit` sensitivity, x1.25 for privileged identities, cap 2.0, and 1.0 on host-only rows. The literal `_risk` fallback is 30 for the user and for the host. `risk_score` applies to both risk objects in the row. A missing user or host is not emitted, so nothing accumulates on `unknown`.
- **Output fields:** `user_display`, `src_display` (the emitted host, else up to 3 hosts comma-separated), `evidence_list`, `model_source_list` (Hugging Face, Ollama, ModelScope), `ai_domain_list`, `model_file_list`, `tool_events`, `weight_events`, `cdn_events`, `mb_in`, `sourcetypes`.
- **Drilldowns:** risk events for the object; model-hub Web activity for the user or hosts (with `bytes_in` and `bytes_out`); model-download DNS lookups for the hosts. Both data drilldowns use `src IN ($src_display$)`, so they also work on a user row with several hosts.
- **MITRE:** T1588.007 (Obtain Capabilities: Artificial Intelligence) and T1105 (Ingress Tool Transfer). `ai_kill_chain_phase=staging`.
- **Cadence:** daily at 01:41 over `-1d@d` to `@d`. Suppression is 23 h on `user,src`. Each user and each host receives risk from this rule at most once a day.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_llm_model_file_download_filter` | `()` | Exclusions inside the Web `tstats` where clause (`Web.*` names), e.g. `NOT sourcetype IN ("aws:waf","aws:elb:accesslogs")` or `NOT Web.user IN ("svc_*")` |
| `hdsi_ai_llm_model_file_download_dns_filter` | `()` | Exclusions inside the DNS `tstats` where clauses, guard included (`DNS.*` names), e.g. a sanctioned GPU subnet, or a resolver below the guard threshold |
| `hdsi_ai_llm_model_file_download_web_scope` | Hub hosts (`huggingface.co`, `hf.co`, `modelscope.cn`, `ollama.com`, `registry.ollama.ai`, Ollama R2 bucket) and app names (`hugging face`, `huggingface*`, `modelscope*`, `ollama*`) | Web pre-filter. Add a hub here and in the common lookups |
| `hdsi_ai_llm_model_file_download_dns_scope` | Weight-serving names only | DNS pre-filter. The hub sites themselves are deliberately excluded |
| `hdsi_ai_llm_model_file_download_tool_hosts` | Regex: `cas-server`/`transfer.xethub*.hf.co`, `registry.ollama.ai` | Hosts where one request proves a model hub client |
| `hdsi_ai_llm_model_file_download_cdn_hosts` | Regex: `cdn-lfs*` (HF, ModelScope), `cas-bridge.xethub*.hf.co`, `*.cdn.hf.co` | Storage CDNs that count only in bulk |
| `hdsi_ai_llm_model_file_download_weight_file_pattern` | Regex on the URL path | Weight-file downloads and Ollama blob pulls (see How it works) |
| `hdsi_ai_llm_model_file_download_min_mb` | `500` | MB from model hub hosts per user or host per day that counts by itself |
| `hdsi_ai_llm_model_file_download_min_cdn_events` | `25` | CDN requests or lookups per user or host per day that count as a bulk fetch |
| `hdsi_ai_llm_model_file_download_shared_src_names` | `10000` | Distinct DNS names per client per day above which the client is treated as a resolver, forwarder or egress |
| `hdsi_ai_llm_model_file_download_untrusted_src` | Public IPv4 | Eval condition for sources that are not your endpoints. Use `false()` if clients have public addresses |
| `hdsi_ai_llm_model_file_download_unstable_src` | IPv6, and `192.168.0.0/16` from `cisco:umbrella*`, `cisco:cloud_security*` or `opendns` sourcetypes | Eval condition (`src`, `sourcetype`) for addresses that do not identify one host from day to day, such as home networks behind a roaming DNS agent. Same treatment as untrusted |
| `hdsi_ai_llm_model_file_download_customizations` | `search *` | Post-scoring hook. Fields are listed in the macro description |
| `hdsi_ai_llm_model_file_download_risk_score` | `search *` | Last pipe. Override `risk_score` (at most 100) |

To allow a sanctioned data-science group, user or GPU host, add a `<entity>|model registry`, `<entity>|local llm` or `<entity>|*` row to `ai_sanctioned_entities` in the common package. `<entity>` is a user, host or `bunit`. A `*|model registry` row allows Hugging Face and ModelScope for the whole organisation.

### Threshold
`..._min_cdn_events` (25) and `..._min_mb` (500) separate model-card browsing from downloads. In the 7-day validation of the previous round (Web and DNS, rule logic, resolvers and public sources excluded), 46 host-days on Tenants A and B had CDN requests or lookups with no model hub client: 43 had 10 or fewer and the highest had 19. The two bulk downloads had about 280 and 296. A 1-day re-check with the query below on the scheduled day agreed: CDN-only host-days peaked at 6 (Tenant A, 7 host-days) and 8 (Tenant B, 2 host-days).

Check your own shape over 7 days before you change them. Run the resolver query further down first and put your resolvers and forwarders in `..._dns_filter`, or their host-days inflate the CDN-only p95:

```spl
| tstats summariesonly=t allow_old_summaries=t count from datamodel=Network_Resolution
    where `hdsi_ai_llm_model_file_download_dns_scope` NOT DNS.src IN ("unknown","-") `hdsi_ai_llm_model_file_download_dns_filter`
    by _time span=1d DNS.src DNS.query DNS.message_type
| stats max(count) as count by _time DNS.src DNS.query
| rename DNS.* as * | eval host=query
| append [| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count from datamodel=Web
    where `hdsi_ai_llm_model_file_download_web_scope` `hdsi_ai_llm_model_file_download_filter`
    by _time span=1d Web.src Web.url_domain Web.site
  | rename Web.* as * | eval host=if(url_domain="unknown",site,url_domain)]
| eval src=lower(src), host=replace(replace(lower(host),":\d+$",""),"\.$",""),
    host=if(match(host,"^dd20bb891979d25aebc8bec07b2b3bbc\.r2\."),"registry.ollama.ai",host)
| where src!="unknown" AND NOT (`hdsi_ai_llm_model_file_download_untrusted_src`)
| eval tool=if(match(host,`hdsi_ai_llm_model_file_download_tool_hosts`),count,0),
    cdn=if(match(host,`hdsi_ai_llm_model_file_download_cdn_hosts`),count,0)
| stats sum(tool) as tool sum(cdn) as cdn by _time src
| where cdn>0
| eval day_type=if(tool>0,"with model hub client","CDN only")
| stats count as host_days dc(src) as hosts perc50(cdn) as p50_cdn perc95(cdn) as p95_cdn max(cdn) as max_cdn by day_type
```
Keep `..._min_cdn_events` above the `CDN only` p95 and max. The `with model hub client` group is already detected through the client hosts.

`..._shared_src_names` (10,000) uses the same derivation as `hdsi_ai_dns_queries_to_ai_domains`. In validation, the hosts that pulled models resolved at most about 5,000 names a day. Resolvers resolved 11,000 to 380,000. Find your resolvers over one full day:

```spl
| tstats summariesonly=t allow_old_summaries=t dc(DNS.query) as names from datamodel=Network_Resolution
    where NOT DNS.src IN ("unknown","-","0.0.0.0","127.0.0.1","::1") by DNS.src
| where names>=2000 | sort - names
```

### Known false positives / Limitations
- **Resolvers as DNS clients.** On Tenant A, every DNS hit for a model host came from three internal resolvers (108,000 to 380,000 names a day). The shared-source guard drops them. Without it, the rule would have put a model download on a DNS server. If your forwarders resolve fewer than 10,000 names a day, add them to `..._dns_filter`.
- **Uploads look like downloads.** `cas-server.xethub.hf.co` and `registry.ollama.ai` also receive uploads (`huggingface_hub` uploads and `push_to_hub`, `ollama push`). DNS evidence cannot tell pull from push, so the evidence is labelled "model hub client". An upload of a model or dataset to a public hub is the more serious event (possible exfiltration of internal data or a fine-tuned model). Check `bytes_out` in the Web drilldown; for DNS-only rows, check the endpoint's process and network data.
- **Inbound WAF and load-balancer logs.** On Tenant B, more than 600 source-days a week came from internet scanners sending `Host: <uuid>.xethub.hf.co` to the tenant's own load balancers and WAF. They are dropped because their `src` is public and they carry no user. Excluding those sourcetypes in `..._filter` also saves scan time.
- **Roaming and home-network addresses.** On Tenant B the DNS security service logs roaming laptops by their home-network `192.168.x.x` address (7 such sources in 7 days) or an IPv6 address (2), and unrelated laptops share the same home ranges. `..._unstable_src` covers IPv6 and `192.168.0.0/16` from the Cisco Umbrella / Secure Access sourcetypes, so these addresses are never system risk objects and host-only rows from them are dropped. User rows keep the user. If your roaming agent uses another sourcetype or range, add it: `(<shipped definition>) OR (sourcetype="<agent sourcetype>" AND cidrmatch("<range>",src))`. If `192.168.0.0/16` is a stable corporate range in that source, remove the term.
- **Clients with public addresses.** Where clients have public addresses, the default `..._untrusted_src` drops their host-only rows. Change it to `false()` or carve out your ranges.
- **VPN, DHCP and CGNAT pools.** `100.64.0.0/10` is treated as internal because many VPN pools use it. A pool address identifies a person only while the lease lasts:
  - Risk on a host-only row lands on the address, and can later read as risk on whoever holds it. On Tenant A, the single row on the scheduled day was such an address with no user.
  - DNS lookups are credited to a Web user on the same address only within one hour of that user's model-hub Web activity, which limits, but does not remove, cross-attribution when a lease changes hands within the hour.
  - If you cannot tie pool addresses to people, mark the pool as untrusted: remove `OR cidrmatch("100.64.0.0/10",src)` from the internal-range list in `..._untrusted_src`, or wrap the definition as `(<shipped definition>) OR cidrmatch("<your VPN pool>",src)`. Host-only rows from it are then dropped and it is never a system object; rows that carry a user are kept. Better still, get the VPN user into the Web or DNS data.
- **User values that are not users.** One DNS security proxy maps its identity list (`<device>,<site>`) to `user`. The rule uses the value as given. Fix the field mapping in the TA.
- **File-viewer pages are not downloads.** On Hugging Face, `/<repo>/blob/main/model.gguf` is the HTML viewer for a weight file, while `/<repo>/resolve/main/model.gguf` is the download. Only the download endpoint counts.
- **Browser-only downloads of one file** can stay below every gate on host-only URL logs. A single `.gguf` fetched by a browser shows as a few `cas-bridge`/`*.cdn.hf.co` requests. The rule catches it only when the proxy logs the path (weight-file URL) or `bytes_in` (large download).
- **Not every model download is a local LLM.** `huggingface_hub` also fetches embedding models for ordinary data-science work, and `transformers.js` web apps fetch small `.onnx` models in the browser; both count as weight-file URLs when the path is logged. Dataset repositories and training-state files are excluded. The score is deliberately modest (20 to 50 before the multiplier). Allow-list data-science groups.
- **Other sources are out of scope.** Model downloads from GitHub releases, Kaggle, Civitai, Replicate, cloud object storage, container images or internal mirrors (Artifactory, a Hugging Face proxy) are not detected.
- **Network_Traffic is not used.** PAN App-ID `huggingface-base` on Tenant A never exceeded 45 MB per source per hour in 7 days, and the App-ID also covers browsing. It added nothing that the URL logs did not already show.

### Validation
Read-only live tests on 2026-10-09 across 4 production ES tenants (labelled A–D). The search and all 3 drilldowns parse on all tenants. No FATAL or ERROR messages, and no job messages, in any run. v1.0 could not fire: it grouped by `Web.site` and `Web.url_domain` together (most tenants fill only one), counted any 3 hub page views as a download, and put risk on `unknown`; it returned 0 rows on every tenant.

| Tenant | Model-hub data | v1.0 rows (4 h) | v1.1 rows (scheduled day) | v1.1 rows per day (7 days, previous round) | v1.1 runtime (scheduled day) | Notes |
|---|---|---|---|---|---|---|
| A | Firewall URL logs (host-only, no bytes); DNS from network capture and resolver logs | 0 | 1 | 0 to 4 (8 in 7 days) | 107 s | Ollama pulls and Hugging Face Xet client traffic from internal and VPN hosts. Users are rarely in the URL logs, so most rows are host-only. All DNS hits came from resolvers and were dropped |
| B | DNS security service (trailing-dot names, roaming clients) and its proxy; inbound load-balancer and WAF logs | 0 | 0 | 0 to 3 (10 in 7 days) | 31 s | Xet client and Ollama registry traffic, including one Hugging Face plus ModelScope bulk download. Scanner rows in WAF and load-balancer logs were dropped. Of the 10 rows, 2 host-only rows on roaming addresses (one `192.168.x.x`, one IPv6) are now dropped by `..._unstable_src`, and 2 user rows no longer emit their `192.168.x.x` host. The new one-hour attribution window was not re-measured over 7 days |
| C | DNS security service and on-site forwarders; SSE app names in `Web` | 0 | 0 | 0 | 12 s | The only model-host lookups came from a public resolver or egress address (dropped) or stayed below the CDN threshold (browsing) |
| D | Inbound web-server logs and internal DNS only | 0 | 0 | 0 | 7 s | No model hub activity in 7 days. Expected silence |

- **Runtime:** the previous layout ran the guard inside an `append`, where it took about 300 s on Tenant A (76 s as a top-level search), and the whole rule took about 6 minutes. With the guard as the outer search, the scheduled-day run on Tenant A took 107 s and returned the same row.
- **Roaming sources (7 days):** Tenant B's DNS security source had model-host lookups from 7 `192.168.x.x` sources and 2 IPv6 sources, all matched by `..._unstable_src`; its 5 `10.x` sources are not. Tenant C's DNS security source had only `10.x` and public sources, and Tenant A only `10.x`, so the default changes nothing there.
- **Drilldowns:** the v1.0 web drilldown scanned all of `Web` and ran 254 s (Tenant A) and 303 s (Tenant B, cut off). The v1.1 drilldowns are scoped by the model-hub pre-filters and by `risk_entity` or the hosts in `src_display`; the previous round measured 2 to 47 s per drilldown.
- **Evidence mix over 7 days (previous round):** of the 18 rows on Tenants A and B, 16 had model-hub-client evidence, 2 of them together with a bulk CDN fetch, and 2 were bulk CDN fetches only (279 and 296 requests). Scores were 20 to 40; no identity had a multiplier above 1.0.
- **Weight-file pattern (Splunk PCRE, all tenants):** counted a `/resolve/` `.gguf` with `?download=true`, a `/resolve/` `onnx/model_quantized.onnx`, a ModelScope `FilePath=sub%2Fmodel.safetensors`, an Ollama registry `/v2/<name>/blobs/sha256:` pull and the R2 `/v2/blobs/sha256/<xx>/<digest>/data` path (`model_file` = `sha256:<12 hex>`). Did not count `training_args.bin`, `rng_state_0.pth`, a `/datasets/` file under `/resolve/`, a `/blob/` `.gguf`, a `/resolve/` `config.json`, a ModelScope `optimizer.pt`, a ModelScope dataset file, or an Ollama manifest.
- **Synthetic pipeline test (all tenants):** makeresults rows fed through the full post-`tstats` pipeline gave the expected 5 rows:
  - A Web user with a `/resolve/` `.gguf` and Xet-client lookups from the same host within the hour → one user row with the host, model hub client + weight-file URL, 40.
  - Xet-client lookups about 12 hours after the host's only Web user browsed the hub → a host-only row, not credited to that user, 30.
  - An Ollama R2 blob lookup → model hub client, 30.
  - A roaming-agent lookup with a user on a `192.168.x.x` address → a user row with no host emitted, 30.
  - A user with weight-file URLs from two hosts → one user row, `src_display` lists both hosts, no host emitted.
  - Dropped: a roaming-agent `192.168.x.x` lookup with no user, an IPv6 lookup with no user, a source marked by the guard, and a browsing-only Web user.

Expected production volume is about 1 risk event a day on Tenant A, 0 to 2 on Tenant B, and none on C and D. Each user and each host receives risk from this rule at most once a day, scored 20 to 60.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:
- Confirm that egress `Web` data or client DNS data reaches the tenant. Inbound server logs alone produce nothing.
- Run the resolver query from Threshold. Check that the guard catches your resolvers, and list known resolvers and forwarders below 10,000 names a day in `..._dns_filter`.
- Decide how to treat VPN pools and roaming DNS agents (see Limitations).
- If your clients use public addresses, review `..._untrusted_src`.
- Allow-list sanctioned data-science users, groups and GPU hosts in `ai_sanctioned_entities`.

The rule is risk-only (`action.risk = 1`, `action.notable = 0`). The AI risk aggregators decide when accumulated risk becomes a notable. Enabling this rule must be one separately approved change.
