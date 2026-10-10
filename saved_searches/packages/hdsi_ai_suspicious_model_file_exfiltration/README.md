## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule detects a user or host **publishing a model or dataset to an external model hub**: Hugging Face, ModelScope, the Ollama registry, Replicate's `r8.im` model registry or Kaggle. Proprietary model weights, fine-tuned adapters and training datasets are high-value intellectual property, and a model hub is a convenient, rarely blocked place to move them. Evidence is a publish command on an endpoint, an upload-only API request or App-ID on the network, or a large upload volume to a model host. Downloading or browsing models never counts, and neither does inference traffic (chat, embeddings, predictions) wherever the source logs the request host or URL path. The rule runs hourly and creates risk on the user and/or the source host. It does not create a notable.

### What changed in v1.1

The v1.0 rule could not do what its name claims:

* It contained no model-file evidence. It summed `bytes_out` to **any** AI provider, chat services included. On one tenant, ordinary Copilot Studio and GitHub Copilot sessions sent 60 to 210 MB per user per day. More than a dozen users a day would have passed its 5 MB gate.
* It fired only when `asset_lookup_by_str.category` matched the unanchored regex `ml|data.science|gpu|training|jupyter|notebook`. On the validation tenants that regex matched **no** real ML hosts. It did match more than 500 unrelated assets: medical-lab systems and site codes that merely contain the letters "ml", and training-room PCs and training application categories. "notebook" is also a common CMDB word for a laptop. Every other host was excluded.
* `user` and `src` defaulted to the literal `unknown`, which could become a shared risk object.
* The Web drilldown filtered `user`/`src` after a full-window `tstats`, so it ran for 4 to 5 minutes on large tenants.

v1.1 replaces the logic. It restricts destinations to model hosts, drops inference endpoints and requires upload-specific evidence. ML infrastructure is now a +10 score modifier (word-bounded regex) instead of a gate. Unattributable rows are dropped, and inbound load-balancer and WAF logs no longer count as user activity.

### Prerequisites

At least one of these data paths is needed. Each one stands alone.

| Data path | What it needs | What it sees | If absent |
|---|---|---|---|
| Endpoint publish commands | `Endpoint.Processes` accelerated, with the full command line in `Processes.process` (EDR, Sysmon EID 1, or Windows 4688 with command-line auditing) | `hf`/`huggingface-cli upload` (also `python -m huggingface_hub.<cli> upload`), `upload-large-folder`, the git-lfs multipart upload agent, `ollama push`, `cog push`, the Kaggle model-version upload (`kaggle models variations create`, `kaggle models variations versions create`, the legacy `instances` spelling and the `m`/`i`/`v` aliases), `kaggle datasets create/version` (also `kaggle d ...`), `modelscope upload`, `git push` with a hub URL on the command line (options such as `-C` or `--force` may come first), the git-lfs `pre-push` hook for a hub remote, the `--push_to_hub` / `--push-to-hub` flag of Transformers, TRL, diffusers and accelerate training scripts, inline `push_to_hub(`, and `huggingface_hub`/`HfApi` `upload_folder`/`upload_file`/`create_commit` calls | No command evidence. `process_name`-only data such as WinHostMon is useless here. A bare `git push origin main` carries no URL (see Limitations). |
| Firewall App-ID | `Network_Traffic` with Palo Alto App-ID in `All_Traffic.app` and `bytes_out` | The `huggingface-upload` App-ID, and upload volume to `huggingface-base` | No App-ID evidence. Firewalls that log only `ssl`/`web-browsing` contribute nothing. |
| Proxy / SSE | `Web` with `url_domain` or `site`, plus `bytes_out` and, for upload-API evidence, `http_method` and the URL path (decrypting proxy) | Hugging Face Xet xorb/shard uploads, model/dataset `preupload` and `xet-write-token` calls, Git LFS upload verify, OCI blob uploads and manifest pushes (Ollama, Replicate `r8.im`), large uploads (also from SSE app names such as Netskope `Hugging Face`) | No Web evidence. Firewall URL logs without a method or path see only domains, which is not enough. |

Also required:
* Common package `hdsi_ai_rba_common`: `ai_domains_filter` (resolves hosts, App-IDs, SSE app names and the endpoint branch's target hub to providers; rows that do not resolve to an enabled `usage_type` `model_registry`/`local_llm` row are dropped, so Replicate counts only through its `r8.im` registry row and `api.replicate.com`/`replicate.com` never count), `ai_unsanctioned_filter(3)` and `ai_risk_multiplier`.
* ES lookups: `identity_lookup_expanded` (`bunit` is used for the multiplier and group allow-listing) and `asset_lookup_by_str` (`bunit` and `category` for the ML-infrastructure modifier, matched on `ip`, `dns`, then `nt_host` so short endpoint hostnames resolve). Both are optional at runtime. A missing match just leaves the multiplier at 1.0 and the modifier at 0.

### How it works

* **Web branch:** `tstats` on `Web`, scoped inline to model-host domains and SSE app names (`_web_scope`), grouped by `user`, `src`, `url_domain`, `site`, `http_method` and `url`. An upload-API request is a POST/PUT/PATCH whose path matches `_upload_url_regex`. Rows whose host and path match `_inference_regex` (the Hugging Face Inference Providers router, the serverless inference API, the hub inference proxy, `/hf-inference/` paths, and `/v1/chat/completions`-style or `/v1/predictions`/`/v1/files` paths) are dropped first, so inference uploads do not count as volume. On SSE rows that carry only an app name in `site` (for example Netskope `Hugging Face`), the host is taken from `Web.url` when the URL carries one, so `router.huggingface.co/hf-inference/...` is recognised there too. An SSE row with neither a host nor a path cannot be classified and still counts toward volume.
* **Network_Traffic branch:** `tstats` on `Network_Traffic`, scoped to model-hub App-IDs (`_traffic_scope`). The PAN `-base` suffix is stripped before provider resolution. An App-ID matching `_upload_app_regex` (`huggingface-upload`) is upload evidence. Replicate App-IDs are out of scope because they carry inference traffic.
* **Endpoint branch:** `tstats` on `Endpoint.Processes` with a broad inline pre-filter (`_process_scope`). The precise `_upload_tool_regex` then confirms a publish command. Downloads such as `hf download`, `ollama pull` and `git clone`, `kaggle models create` (metadata only), `--push_to_hub False`, a bare `upload_folder(` from another SDK, and `git push` without a hub URL never match. A hub hostname must be a whole host label, so remotes such as `gitlab.examplehf.com` or `myhf.corp` do not match `hf.co`. The target hub is set from the tool verb (`ollama push` = `registry.ollama.ai`, `cog push` = `r8.im`, `kaggle models|datasets|m|d` = `kaggle.com`, `modelscope` = `modelscope.cn`, otherwise `huggingface.co`), not from a substring of the repository path. Secrets are masked before the command reaches the risk message: Hugging Face (`hf_…`) and Replicate (`r8_…`) tokens, URL userinfo (`https://user:password@host` becomes `https://***@host`), and the value after `--token`, `--api-key`, `--password`, `token=`, `api_key=`, `password=` or `Authorization: Bearer|Basic`.
* **Provider resolution:** all three branches go through `ai_domains_filter`, so the provider names and the `enabled` flags in the common lookups apply to every path, the endpoint one included. Disabling a provider row (for example `kaggle.com`) silences its Web, App-ID and command evidence alike. Only rows that resolve to `model_registry` or `local_llm` are kept.
* Identity cleanup:
  * Empty or placeholder users, IPv4- or IPv6-shaped users, `SYSTEM`/service accounts and machine accounts (`…$`) are nulled. Users and hosts are lowercased, so the same account seen in different case by EDR and the proxy is one risk object.
  * A public `src` (`_untrusted_src`: public IPv4 or global-unicast IPv6) is never a risk object. Rows without a user and without a trusted `src` are dropped. This removes inbound AWS ELB/WAF and IIS logs, which carry internet clients that send model-hub Host headers.
* Results are aggregated per user/host pair and provider. Sanctioned entities are removed (`ai_unsanctioned_filter`), then the remaining rows are aggregated per user/host pair.
* A row survives when at least one piece of evidence holds:
  * `publish command`: one command is enough.
  * `upload App-ID`: at least `_min_evidence_mb` sent with the upload App-ID.
  * `upload API request`: at least `_min_evidence_mb` sent, or the source does not log bytes. The hub `commit` endpoint and Space repositories are not upload paths, so a bytes-less web-UI README or model-card edit does not count.
  * `large upload`: at least `_min_mb` sent to model hosts in the hour.
* **Scoring:**
  * Base score is 45 for a publish command, 40 for upload App-ID or API evidence, and 35 for volume only.
  * Add 10 when more than one kind of evidence is present, and 10 when the source asset category matches `_ml_asset_regex`.
  * The result is multiplied by `risk_multiplier` (identity bunit sensitivity, ×1.25 for privileged identities, capped at 2.0), then bounded: `risk_score = min(70, max(10, …))`.
  * `risk_score` applies to both risk objects in the row. The literal `_risk` fallbacks are user 40 and system 30.
* Suppression is per `user,src` for 24 hours.

### Tuning macros

| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_suspicious_model_file_exfiltration_filter` | `()` | Inline exclusions for the Web tstats (e.g. `NOT sourcetype IN ("aws:elb:accesslogs","aws:waf")`) |
| `hdsi_ai_suspicious_model_file_exfiltration_traffic_filter` | `()` | Inline exclusions for the Network_Traffic tstats (e.g. a sanctioned training subnet) |
| `hdsi_ai_suspicious_model_file_exfiltration_process_filter` | `()` | Inline exclusions for the Endpoint tstats (e.g. CI/CD runners that publish models) |
| `hdsi_ai_suspicious_model_file_exfiltration_web_scope` | model-host domains + SSE app names | Destinations considered for Web data |
| `hdsi_ai_suspicious_model_file_exfiltration_traffic_scope` | `huggingface*`, `ollama*`, `modelscope*`, `kaggle*` App-IDs | Destinations considered for firewall data (only Hugging Face and `kaggle` App-IDs resolve today) |
| `hdsi_ai_suspicious_model_file_exfiltration_process_scope` | broad command-line wildcards | Pre-filter for the endpoint branch |
| `hdsi_ai_suspicious_model_file_exfiltration_upload_tool_regex` | publish-command regex | Decides what counts as a publish command |
| `hdsi_ai_suspicious_model_file_exfiltration_upload_url_regex` | upload-only API paths (no `commit`, no Spaces) | Decides what counts as an upload-API request |
| `hdsi_ai_suspicious_model_file_exfiltration_upload_app_regex` | `-upload$` | Upload App-IDs (firewall `All_Traffic.app` only; not applied to SSE app names) |
| `hdsi_ai_suspicious_model_file_exfiltration_inference_regex` | HF router / inference API / inference proxy, `/hf-inference/`, `/v1/chat/completions`-style, `/v1/predictions`, `/v1/files` | Web host (or the host in an SSE row's URL) + path dropped as inference |
| `hdsi_ai_suspicious_model_file_exfiltration_min_mb` | `100` | MB per user/host pair per hour to model hosts that counts on its own |
| `hdsi_ai_suspicious_model_file_exfiltration_min_evidence_mb` | `10` | Minimum MB for App-ID or upload-API evidence when bytes are logged |
| `hdsi_ai_suspicious_model_file_exfiltration_ml_asset_regex` | word-bounded ML/GPU/data-science regex | Asset categories that add +10 |
| `hdsi_ai_suspicious_model_file_exfiltration_untrusted_src` | public IPv4 or global-unicast IPv6 | `src` values that are never a risk object |
| `hdsi_ai_suspicious_model_file_exfiltration_customizations` | `search *` | Post-scoring hook |
| `hdsi_ai_suspicious_model_file_exfiltration_risk_score` | `search *` | Last-pipe score override (max 100) |

To permit a team that legitimately publishes to the organisation's own hub account, add an `ai_sanctioned_entities` row. The key is `<user, host or group>|<provider>` in lower case, for example `mlops_svc|model registry`, `gpu-node-01|*` or `<bunit>|*`. The group is the rule's `bunit` field (the user's ES identity `bunit`, else the source asset's `bunit`); for a user without one, the common macro also tries the ES identity `bunit` of the bare user name. `*|<provider>` permits a provider organisation-wide, for example `*|replicate`. Provider names here are `Model Registry` (Hugging Face, ModelScope and Kaggle share it), `Local LLM` (Ollama) and `Replicate` (`r8.im`). An optional `expires` date can be set. Do not widen the filters for this.

### Threshold

`_min_mb` defaults to 100 MB per user/host pair per hour. A small quantised LLM is hundreds of MB and a full model is GB-scale. In 7 days of validation data the largest hourly upload to a model hub from one entity was about 1 MB on firewall App-ID data. No SSE user sent more than 25 MB to any model-hosting site in the whole week. Before lowering it (for example to catch LoRA adapters), measure your own hourly upload shape:

```
| tstats summariesonly=t allow_old_summaries=t sum(All_Traffic.bytes_out) as bytes_out
  from datamodel=Network_Traffic where `hdsi_ai_suspicious_model_file_exfiltration_traffic_scope`
  by All_Traffic.user All_Traffic.src All_Traffic.app _time span=1h
| eval mb=bytes_out/1048576
| stats count as entity_hours perc99(mb) as p99_mb max(mb) as max_mb by All_Traffic.app
```

Run the same query against `Web` (`sum(Web.bytes_out)`, `_web_scope`, `by Web.user Web.src Web.url_domain Web.site _time span=1h`) if a proxy or SSE logs bytes. Set `_min_mb` well above the observed `max_mb`, at least 5 × p99. `_min_evidence_mb` (10 MB) only needs to stay above a hub web-UI edit of a model card or README, which is a few KB.

### Known false positives / Limitations

* **Legitimate publishing.** ML teams that publish open models, and CI jobs that push to the organisation's hub account, will fire. Allow-list them with `ai_sanctioned_entities` (user, host, bunit or organisation-wide; provider `model registry`, `local llm` or `replicate`), or add a CI runner to `_process_filter`. The rule cannot see which hub organisation or repository was the target, so a personal account and the corporate account look the same. Hugging Face, ModelScope and Kaggle share the common provider name `Model Registry`, so a provider-scoped allow-list entry covers all three.
* **A bare `git push` is invisible on the command line.** Real pushes name a remote (`git push`, `git push origin main`), so the hub URL is not in `Processes.process`. In 7 days, every `git push` on the validation tenants (about 700 events on Tenant A, 9 on Tenant C) had no URL. The rule catches `git push` only when a hub URL is typed (with or without options such as `--force` or `-C <dir>`), and through the git-lfs `pre-push` hook (`git lfs pre-push <remote> <hub URL>`), which runs for LFS-tracked repos, as model repos usually are. No validation tenant logged a `pre-push` process in 7 days, so that path is proven only synthetically. A bare push to a non-LFS hub repo is visible only to the network paths (Xet/LFS upload paths or volume).
* **Legacy Git LFS uploads bypass the hub's hosts.** Older Hugging Face repos upload LFS objects to presigned S3 URLs, and Ollama pushes are redirected to the R2 bucket. Those bytes are only counted where the host is in scope (the R2 bucket is). The `preupload` and `xet-write-token` calls on `huggingface.co` remain visible to a decrypting proxy, and the endpoint command remains visible to EDR.
* **Bytes-less upload-path evidence.** On a source that logs method and path but no bytes, one POST/PUT/PATCH to an upload path is enough (score 40). The hub `commit` endpoint and Space repositories are excluded because a web-UI README or model-card edit and a Space code commit look identical there. A programmatic `upload_file` of a small file still calls `preupload` and will fire; that is a publish, but it may not be a model.
* **Firewall URL logs carry little evidence.** On the tenant whose Web data is Palo Alto URL/threat logs, `bytes_out` is 0% and `http_method` is mostly empty, so its Web rows can never produce volume evidence. They can produce bytes-less upload-path evidence when PAN logs a POST to an upload path; in the validation week Tenant A logged at most one POST to a model host and none to an upload path. The same tenant's `Network_Traffic` App-ID data is the stronger path.
* **App-ID and SSE app-name volume includes inference.** `huggingface-base` covers the whole hub, including inference calls, and cannot be split by path. An SSE row that logs only the app name (no URL) cannot be split either. Only volume above `_min_mb` (100 MB/hour) counts there, far above any hourly volume seen in validation. Replicate App-IDs and `api.replicate.com` are out of scope for the same reason; Replicate counts only through `r8.im` (proxy) and `cog push` (EDR).
* **Training scripts with `--push_to_hub`.** The flag means the script uploads the trained model to the hub when it finishes, so the command counts as a publish when it starts, even if the job later fails. It also fires for `--push_to_hub True`; it does not fire for `False`, `0` or `no`.
* **Process command lines.** Endpoint data without `Processes.process` (WinHostMon) or with 4688 command-line auditing off sees nothing. A renamed binary or a custom Python script that calls the HTTP API directly without `huggingface_hub`/`HfApi` in the command line is not caught by the command regex. Use the network paths for those.
* **Short-hostname assets.** Asset enrichment tries `ip`, `dns` and `nt_host`. Hosts missing from the ES asset list get no ML-infrastructure modifier and no bunit.
* **Provider coverage depends on the common lookups.** Every path, the endpoint one included, is resolved by `ai_domains_filter`. Hostnames that resolve today: `huggingface.co` and `hf.co` (with subdomains such as the Xet storage hosts), `modelscope.cn`, `ollama.com`, `registry.ollama.ai` and its R2 blob bucket, `r8.im` and `kaggle.com`. App names that resolve today: `hugging face`, `huggingface`, `huggingface-base`, `huggingface-upload` and `kaggle` (the PAN `-base` suffix is stripped first). `ollama*` and `modelscope*` App-IDs or SSE app names are pre-selected by the scope macros but are dropped until the common `ai_provider_apps` lookup lists them. Kaggle is a general data-science platform; the common registry gives it a lower weight, but this rule scores it like any model hub. On Tenant C, 23 MB went to the Netskope `Kaggle` app over the validation week, well below `_min_mb`.
* **Exfiltration via chat assistants** (pasting or attaching files to ChatGPT, Copilot or Claude) and model inference (`_inference_regex`) are out of scope. Large uploads to those services are routine, so this rule does not treat them as model exfiltration.

### Validation

Read-only searches on 4 production ES tenants, 2026-10-09. Rule windows: 4h (`auto`), 24h and 7 days for the earlier v1.1 build; the final build was re-run at 4h only (with parse checks of the rule and its 4 drilldowns). Synthetic tests fed crafted rows through the full pipeline.

| | Tenant A | Tenant B | Tenant C | Tenant D |
|---|---|---|---|---|
| Model-host data present | PAN App-ID (`huggingface-base`; max ~1 MB/entity-hour); URL/threat logs without bytes, no POST to an upload path | Umbrella proxy downloads only (one global-IPv6 src, now untrusted); inbound ELB/WAF with spoofed hub Host headers | Netskope (no hub uploads; 23 MB/week to the `Kaggle` app, which now resolves but stays far below `_min_mb`); PAN App-ID (KB-scale) | none (inbound IIS only) |
| Endpoint command lines | yes: ~700 `git push` in 7d, none with a URL; no `pre-push`; no publish commands | sparse | yes: 9 `git push` in 7d, none with a URL; no publish commands | sparse |
| v1.0 result (4h) | 0 rows (asset gate), Web drilldown 257s | 0 rows, rule 167s, drilldown 304s | 0 rows | 0 rows |
| v1.1 parse (rule + 4 drilldowns) | OK | OK | OK | OK |
| v1.1 rows, 4h / 24h / 7d (earlier build) | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 |
| v1.1 runtime, 4h / 24h / 7d (earlier build) | 23s / 44s / 197s | 8s / 34s / 233s | 8s / 8s / 20s | 6s / 7s / 9s |
| Final build, 4h: rows / runtime / errors | 0 / 20s / none | 0 / 7s / none | 0 / 7s / none | 0 / 7s / none |
| Widened process pre-filter, 7d | 0 command lines | 0 | 0 | 0 |
| Old asset-category regex hits | 500+ unrelated assets (medical lab, training rooms, site codes) | 0 | 3 (a training application) | 0 |
| New `_ml_asset_regex` hits | 0 | 0 | 0 | 0 |

The first synthetic run (19 expected detections, 19 negatives dropped) covered the Web, App-ID and command paths:
* Xet xorb upload of 300 MB: `upload API request` + `large upload`, score 50. The same from a user with a global IPv6 src: user-only risk, score 50.
* `r8.im` OCI blob upload of 200 MB: provider Replicate, score 50.
* SSE "Hugging Face" app with 150 MB sent: user-only risk, score 35.
* PAN `huggingface-upload` with 50 MB: system-only risk, score 40. PAN `huggingface-base` with 150 MB: score 35.
* Bytes-less `preupload` POST: score 40.
* `hf upload`, `python -m huggingface_hub.commands.huggingface_cli upload`, `HfApi().upload_folder(`, `push_to_hub(`, `kaggle models instances versions create`, `ollama push`, `git push --force <hub URL>`, `git -C <dir> push <hf.co URL>`, `git lfs pre-push origin <hub URL>` and `git-lfs.exe pre-push origin <hub URL>`: score 45 each. `git push` to a hub as `SYSTEM` puts the risk on the host only.
* Negatives: hub browsing; small and bytes-less `commit` POSTs (model and Space); inbound ELB/WAF rows from public IPv4/IPv6 clients with no user; 130 MB to `router.huggingface.co/v1/chat/completions`; 150 MB to the hub inference proxy, `api.replicate.com/v1/files` and `replicate.com`; PAN `replicate-base` with 150 MB; `huggingface-base` with 1 MB; `ollama pull`, `hf download`, `git push origin main`, a commit message mentioning `huggingface.co`, `git lfs pre-push` to a non-hub remote, Box SDK `upload_folder(`.

The final synthetic run (Tenant C, through the final SPL and the current common lookups) produced the 13 expected detections and dropped all 8 negatives:
* Detected: Xet upload of 300 MB plus a 1 MB browse by the same user in upper case, merged into one row (score 50); SSE `Kaggle` app with 300 MB and PAN `kaggle-base` with 200 MB (provider Model Registry, score 35); SSE `Hugging Face` with 150 MB and no URL (score 35); `r8.im` blob upload (Replicate, score 50); 150 MB to the Ollama R2 bucket (Local LLM, score 35); PAN `huggingface-upload` 50 MB (host only, score 40); `kaggle models variations create`, `kaggle m v create`, `python run_clm.py --push_to_hub ... --hub_token hf_…` (token value masked), `git push https://user:password@huggingface.co/...` (userinfo masked), `ollama push` (Local LLM) and `cog push` (Replicate), score 45 each.
* Dropped: SSE `Hugging Face` rows of 150 MB whose URL is `https://router.huggingface.co/hf-inference/...` or `router.huggingface.co/v1/chat/completions`; hub browsing of 2 MB; an inbound `preupload` POST from a public IP with no user; PAN `ollama-base` with 300 MB (App-ID not in the common lookups); `git push https://gitlab.examplehf.com/...`; `kaggle models create`; `--push_to_hub False`.

An offline regex harness additionally confirmed `kaggle models variations versions create`, `kaggle d create`, `python -m kaggle models instances versions create`, `accelerate launch train.py --push_to_hub`, `--push-to-hub`, `--push_to_hub=True` and `git push git@hf.co:...` match, while `git push origin https://myhf.corp/...`, `git push https://hf.com/...`, `--push_to_hub_token x`, `--push_to_hub=false` and `kaggle d download` do not.

Zero rows on real data is the expected steady state for this rule: no tenant uploaded models to a hub in the validation week.

### Deployment

The package ships with `enable_alerting: false`. It is risk-only (`action.notable = 0`), and its score is bounded at 70 per event, so the AI risk aggregators decide on escalation. Before enablement:

* Confirm which of the three data paths the tenant has (see Prerequisites).
* Run the threshold query above.
* Allow-list teams that publish models legitimately.
* Measure a week of suppressed risk output.

Enabling this rule must be a separately approved change.
