# Detection Template

**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This page is the copy-paste starting point for a new HDSI AI detection package. A detection is one package under `saved_searches/packages/hdsi_ai_<name>/`, built to the soc-search-repo gold conventions. [CONTRIBUTING.md](CONTRIBUTING.md) covers the workflow (naming, scoring, README, live testing, tests). [ARCHITECTURE.md](ARCHITECTURE.md) covers the common macros and the aggregators that consume the risk.

Replace every `<...>` placeholder. The worked example at the end parses on all 4 validation tenants. It shows a complete package, but it is not a shipped detection.

## Package layout

```
saved_searches/packages/hdsi_ai_<name>/
  package.yml
  README.md
  confs/savedsearches.conf
  confs/macros.conf
```

The package directory name is the package ID. It is also the `detection_id` value, the macro prefix, and the key that `ai_mitre_mapping.csv` and the multi-vector aggregator use.

## package.yml

```yaml
version: 1.1.0
creation_date: '<YYYY-MM-DD>'
package_title: AI <Title>
description: "<What it detects, which data it reads, what it emits (risk on user/system, no notable).>"
author: Hurricane Labs
app_compatibility:
  - app_name: SplunkEnterpriseSecuritySuite
    operator: '*'
    required_version: '*'
app_context: HurricaneLabsContentUpdates
enable_alerting: false
common_dependencies:
  - macros:ai_domains_filter            # only the common macros the search really calls
  - macros:ai_unsanctioned_filter(3)
  - macros:ai_risk_multiplier
tags:
  - rba_only                            # every tag must exist in saved_searches/package_tags.csv
  - web
data_prereqs:
  datamodels:
    op: OR                              # AND if every model is required, OR if any one is enough
    items:
      - Web
      - Network_Traffic
deployment_type: global                 # adhoc if real results need rare data or setup
prereq_packages:
  - hdsi_ai_rba_common
```

| Key | Rule |
|---|---|
| `version` | `1.1.0` for this release. `tests/conftest.py::RELEASE_VERSION` enforces one version across the repo. |
| `enable_alerting` | Always `false`. Enablement is a separate, per-tenant approved change. |
| `data_prereqs` | What the search really needs. CIM names only: the DLP model is `DLP` (dataset `DLP.DLP_Incidents`), never `Data_Loss_Prevention`. Add `searches:` items (`\| tstats ... \| where count > 0`) when a field or source, not just the model, decides whether the rule can work. |
| `deployment_type` | `global` when the rule ran with real data on at least one validation tenant and its data is common. `adhoc` when it produced real results but needs data or setup most tenants lack; the README then states the exact requirement. A rule that no tenant could run on real data is not released: it goes to `saved_searches/incubating/`. Never delete a weak rule. |
| `tags` | Only values listed in `saved_searches/package_tags.csv` (`validate.py` rejects others). |
| `prereq_packages` | Must include `hdsi_ai_rba_common`. |

## macros.conf

```ini
[hdsi_ai_<name>_filter]
definition = ()
description = v1.1 Tenant exclusion hook, applied inside the <Model> tstats where clause. Use <Model>.* field names, e.g. NOT <Dataset>.src IN ("10.1.1.10"). Ships empty.
disabled = False
iseval = 0

[hdsi_ai_<name>_scope]
definition = (<Dataset>.<field> IN ("<value>","<value>"))
description = v1.1 Inline tstats pre-filter. <What it covers, where the values come from (ai_provider_domains / ai_tool_processes), how to regenerate it>.
disabled = False
iseval = 0

[hdsi_ai_<name>_min_<unit>]
definition = <n>
description = v1.1 <What the threshold counts, per what entity and window>. <Live evidence for the default>.
disabled = False
iseval = 0

[hdsi_ai_<name>_customizations]
definition = search *
description = v1.1 Tenant customization hook, piped after aggregation and scoring (fields: <list>). Ships as search *.
disabled = False
iseval = 0

[hdsi_ai_<name>_risk_score]
definition = search *
description = v1.1 Risk score customization hook, last pipe. Adjust or override risk_score (integer, at most 100) per tenant. Ships as search *.
disabled = False
iseval = 0
```

- `_filter`, `_customizations` and `_risk_score` are mandatory. Every other macro is a named threshold or list, so a tenant can tune it without editing the search.
- Every macro `description` starts with `v1.1 ` and says **why** the default is what it is, with evidence where there is some.
- A `_filter` definition is a bare boolean expression. Never write `NOT \`..._filter\``, and never pipe it.

## savedsearches.conf

```ini
[<Domain> - HDSI AI <Title> - Rule]
action.correlationsearch.enabled = 1
action.correlationsearch.label = HDSI AI <Title>
action.correlationsearch.annotations = {"mitre_attack": ["<T####[.###]>"]}
action.customsearchbuilder.enabled = 0
action.customsearchbuilder.spec = {}
action.email = 0
action.notable = 0
action.notable.param.drilldown_dashboards = []
action.notable.param.drilldown_searches = [{"name":"View associated risk events for $user$","search":"| from datamodel:\"Risk.All_Risk\" | search risk_object=\"$user$\" source=\"*HDSI AI*\" | table _time, source, risk_score, risk_object, risk_object_type, risk_message | sort - _time","earliest_offset":"$info_min_time$","latest_offset":"$info_max_time$"},{"name":"<Evidence drilldown name with $token$>","search":"<evidence SPL>","earliest_offset":"$info_min_time$","latest_offset":"$info_max_time$"}]
action.notable.param.rule_description = <One or two sentences with $tokens$ naming the object and the evidence.>
action.notable.param.rule_title = HDSI AI <Title> ($user$ <context>)
action.notable.param.security_domain = <network|endpoint|identity|access|threat|audit>
action.notable.param.severity = <informational|low|medium|high>
action.notable.param.verbose = 0
alert.digest_mode = 1
action.risk = 1
action.risk.param._risk = [{"risk_object_field":"user","risk_object_type":"user","risk_score":<n>},{"risk_object_field":"src","risk_object_type":"system","risk_score":<n>}]
action.risk.param._risk_message = <One sentence with $tokens$: who, what, how much, where.>
action.risk.param._risk_score = 0
action.risk.param.verbose = 0
alert.managedBy =
alert.suppress = 1
alert.suppress.fields = user,src
alert.suppress.period = 86400s
alert.track = 1
allow_skew = 5m
counttype = number of events
cron_schedule = <M> * * * *
description = v1.1.0 <What it detects, the data path, what it excludes and what it emits. Risk only, no notable.>
disabled = 0
dispatch.earliest_time = -65m@m
dispatch.latest_time = -5m@m
dispatch.rt_backfill = 1
dispatch.ttl = 2p
enableSched = 1
realtime_schedule = 0
relation = greater than
quantity = 0
request.ui_dispatch_app = SplunkEnterpriseSecuritySuite
schedule_window = auto
search = | tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count min(_time) as firstTime max(_time) as lastTime from datamodel=<Model> where `hdsi_ai_<name>_scope` `hdsi_ai_<name>_filter` by <Dataset>.user <Dataset>.src <Dataset>.<evidence> \
	| rename <Dataset>.* as * \
	| <normalise: null placeholders, lowercase, set ai_domain or process_name_lc> \
	| `ai_domains_filter` \
	| <aggregate per entity; apply `hdsi_ai_<name>_min_<unit>`> \
	| `ai_unsanctioned_filter(user,src,provider)` \
	| `ai_risk_multiplier` \
	| eval risk_score=min(<cap>, max(<floor>, round(<base> * coalesce(tonumber(severity_weight),1) * coalesce(risk_multiplier,1)))) \
	| convert ctime(firstTime) ctime(lastTime) \
	| eval ai_activity="<activity>", detection_id="hdsi_ai_<name>", mitre_attack="<T####>", ai_kill_chain_phase="<phase>" \
	| `hdsi_ai_<name>_customizations` \
	| `hdsi_ai_<name>_risk_score`
```

### Key reference

| Key | Rule |
|---|---|
| Stanza | `[<Domain> - HDSI AI <Title> - Rule]`. Domain is `Network`, `Endpoint`, `Identity`, `Audit` or `Threat`. Title case, no detection number. |
| `action.correlationsearch.label` | The stanza without the domain prefix and without ` - Rule`. |
| `action.correlationsearch.annotations` | Valid JSON, `{"mitre_attack": [...]}`, 1-4 current ATT&CK IDs (AI tooling acquisition is `T1588.007`). The SPL `mitre_attack` eval matches the annotation. |
| `action.notable` | `0`. Keep every `action.notable.param.*` line anyway: the drilldowns, `rule_title` and `rule_description` are used if a tenant promotes the rule, and the drilldowns are needed for testing. |
| `action.notable.param.drilldown_searches` | A JSON list of `name`, `search`, `earliest_offset`, `latest_offset`. Risk drilldowns use `\| from datamodel:\"Risk.All_Risk\" \| search ...`. `from ... where` is a fatal error. Web drilldowns group `by ... Web.url_domain Web.site` with `fillnull_value`. |
| `action.risk` | `1`. |
| `action.risk.param._risk` | A JSON list. Every entry has `risk_object_field`, `risk_object_type` (`user` or `system`) and a **literal integer** `risk_score` from 1 to 100. `$token$` scores are not supported in ES 8; the integer is the fallback when SPL sets no `risk_score`. |
| `action.risk.param._risk_message` | One sentence with `$tokens$` that names the object and the evidence. Never use `$_x$` tokens: fields that start with `_` are dropped from risk events. |
| `alert.suppress.fields` | The risk object field(s), optionally with the provider. |
| `alert.suppress.period` | In seconds (`86400s`). For daily rules use slightly less than 24 h (`72000s`-`82800s`) so the next day's run is not suppressed. |
| `cron_schedule` / `dispatch.*` | Pairs: 5 min `*/5` with `-15m@m` to `-5m@m`; 15 min `N-59/15` with `-20m@m` to `-5m@m`; hourly `M * * * *` with `-65m@m` to `-5m@m`; daily `M H * * *` with `-1d@d` to `@d`. Pick an unused minute offset. |
| `description` | Starts with `v1.1.0 `, then a plain description ending with what the rule emits ("Risk only, no notable."). |
| `search` | Continuation lines end with ` \`. Every line after the first starts with a tab and `\| `. The last line has no backslash (`validate.py` rejects a trailing backslash at the end of the file). |

### Search rules

1. **Inline filter.** `` `hdsi_ai_<name>_filter` `` sits inside the first `tstats ... where` (or the base search) and uses data model field names. Piping it (`| ()`) is a fatal parse error. That mistake once broke all 50 searches.
2. **Pre-filter the tstats.** Scope the `where` clause to the evidence (domains, App-IDs, process names, ports) and let the common macros decide exactly. On Tenant A the example below took 73 s per hour unscoped and 4 s scoped. A hard-coded list must contain only values that are enabled in the matching lookup; `tests/test_lookup_sync.py` checks the listed packages.
3. **Web: carry both `url_domain` and `site`.** Group `by ... Web.url_domain Web.site` with `fillnull_value="unknown"` (tstats drops a row when any `by` field is null), then set `ai_domain=lower(coalesce(nullif(url_domain,"unknown"),nullif(site,"unknown")))`. SSE proxies fill only `site`, with an application name. Firewall URL logs fill only `url_domain`.
4. **DNS: resolve distinct queries.** Aggregate by `src query` before `` `ai_domains_filter` ``, set `ai_input_type="dns"`, and expect trailing-dot answers (the resolver strips them).
5. **Multivalue input.** `ai_domains_filter` resolves only the first value; `mvexpand` first and count before expanding.
6. **No placeholder risk objects.** Null `unknown`, `-`, empty, IPs-as-users and other placeholders before scoring. Drop the row, or leave that risk object field null so ES does not write it.
7. **Allowlist, then multiplier.** Call `` `ai_unsanctioned_filter(<user>,<system>,provider)` `` with field names, then `` `ai_risk_multiplier` `` (it reads `user`, outputs `risk_multiplier`).
8. **Score.** Set a numeric `risk_score` as `min(<cap>, ...)`. ES uses it for every risk object of the row. Keep the cap modest (30-80; most rules use 60) because the aggregators decide severity. If the user and the system need different scores, keep static scores in `_risk` instead.
9. **Metadata.** Set `ai_activity`, `detection_id="<package>"`, `mitre_attack` and `ai_kill_chain_phase` (`recon`, `initial_access`, `execution`, `staging`, `collection`, `exfiltration`, `lateral_movement`).
10. **Hook order.** `` | `hdsi_ai_<name>_customizations` `` then `` | `hdsi_ai_<name>_risk_score` `` as the **last** pipe.
11. **No double pipes.** A macro definition never starts with `|` where the call site already pipes it.
12. **ES lookups.** `asset_lookup_by_str` is keyed by `asset`, `ip`, `dns`, `mac` or `nt_host` (there is no `key` field). Match `asset_lookup_by_cidr` with `asset as <ipfield>`. `identity_lookup_expanded` has `bunit`, `category` and `priority`, but no `department`.
13. **Backslash users.** `DOMAIN\user` loses the backslash inside a quoted drilldown term. Emit a drilldown-safe field (`replace(user,"[\\\\\"]","*")`) and use it in the drilldown.

## README.md (gold structure)

```markdown
## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

<2-4 sentences: what it detects, why it matters, what it emits (risk on user/system, no notable).>

### Prerequisites
<Required data model and fields, and what breaks if each is absent. ES lookups used. Dependency on hdsi_ai_rba_common.>

### How it works
- <Bullet walk-through of the SPL: scope, normalisation, provider/process resolution, aggregation, thresholds.>
- <Scoring: base score, severity_weight, risk_multiplier, cap, floor.>

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_<name>_filter` | `()` | ... |
| `hdsi_ai_<name>_min_<unit>` | `<n>` | ... |
| `hdsi_ai_<name>_customizations` | `search *` | ... |
| `hdsi_ai_<name>_risk_score` | `search *` | ... |

### Threshold
<How to derive a tenant value, with a copy-paste SPL that applies the same scope and exclusions as the rule.>

### Known false positives / Limitations
<Concrete and backed by evidence from the live tests.>

### Validation
| Tenant | Data present | Parses (rule + drilldowns) | Rows in window | Notes |
|---|---|---|---|---|
| A | | | | |
| B | | | | |
| C | | | | |
| D | | | | |

### Deployment
The package ships with `enable_alerting: false`. It is risk-only (`action.notable = 0`). Before enablement, validate the complete search against the target tenant, confirm the risk objects identify real users or hosts, derive the threshold from that tenant's data and measure the daily risk volume. Enabling this rule is a separately approved change.
```

Use "Tenant A-D" only. Never write customer names, hostnames, usernames, internal domains or IP addresses seen in tenant data. Public AI provider domains and app names are fine. Date the validation table.

## Worked example

This is an illustrative package `hdsi_ai_example_api_access`: a user calling a public model API through the web proxy, scored on the user and the source host. On 2026-10-10 it parsed on Tenants A-D. A one-hour run returned 0 rows on all four tenants, in 4 s on the largest, and without errors. API traffic through the proxy is rare in those tenants, which is why the shipped `hdsi_ai_api_access_from_non_dev_endpoint` also reads DNS and firewall data.

**macros.conf**

```ini
[hdsi_ai_example_api_access_filter]
definition = ()
description = v1.1 Tenant exclusion hook, applied inside the Web tstats where clause. Use Web.* field names, e.g. NOT Web.src IN ("10.1.1.10") for an approved integration server. Ships empty.
disabled = False
iseval = 0

[hdsi_ai_example_api_access_scope]
definition = (Web.url_domain IN ("api.openai.com","api.anthropic.com","generativelanguage.googleapis.com","api.mistral.ai","api.deepseek.com","api.groq.com","api.perplexity.ai") OR Web.site IN ("api.openai.com","api.anthropic.com","generativelanguage.googleapis.com","api.mistral.ai","api.deepseek.com","api.groq.com","api.perplexity.ai"))
description = v1.1 Inline tstats pre-filter: model API hosts (usage_type=api, enabled) from ai_provider_domains. ai_domains_filter makes the exact decision. Scoped, a 1-hour run took 4 s on the largest validation tenant against 73 s unscoped.
disabled = False
iseval = 0

[hdsi_ai_example_api_access_min_requests]
definition = 5
description = v1.1 Minimum API requests per user, source and provider in the hourly window, so that a single SDK health check does not score.
disabled = False
iseval = 0

[hdsi_ai_example_api_access_customizations]
definition = search *
description = v1.1 Tenant customization hook, piped after scoring (fields: user, src, provider, request_count, mb_out, ai_domain_list, risk_multiplier, risk_score, firstTime, lastTime). Ships as search *.
disabled = False
iseval = 0

[hdsi_ai_example_api_access_risk_score]
definition = search *
description = v1.1 Risk score customization hook, last pipe. Adjust or override risk_score (integer, at most 100) per tenant. Ships as search *.
disabled = False
iseval = 0
```

**savedsearches.conf**

```ini
[Network - HDSI AI Example API Access - Rule]
action.correlationsearch.enabled = 1
action.correlationsearch.label = HDSI AI Example API Access
action.correlationsearch.annotations = {"mitre_attack": ["T1588.007"]}
action.customsearchbuilder.enabled = 0
action.customsearchbuilder.spec = {}
action.email = 0
action.notable = 0
action.notable.param.drilldown_dashboards = []
action.notable.param.drilldown_searches = [{"name":"View associated risk events for $user$","search":"| from datamodel:\"Risk.All_Risk\" | search risk_object=\"$user$\" source=\"*HDSI AI*\" | table _time, source, risk_score, risk_object, risk_object_type, risk_message | sort - _time","earliest_offset":"$info_min_time$","latest_offset":"$info_max_time$"},{"name":"View AI API requests by $user$","search":"| tstats summariesonly=t allow_old_summaries=t fillnull_value=\"unknown\" count sum(Web.bytes_out) as bytes_out from datamodel=Web where Web.user=\"$user$\" `hdsi_ai_example_api_access_scope` by Web.user Web.src Web.url_domain Web.site | rename Web.* as * | eval ai_domain=lower(coalesce(nullif(url_domain,\"unknown\"),nullif(site,\"unknown\"))) | `ai_domains_filter` | table user, src, provider, ai_domain, count, bytes_out | sort - count","earliest_offset":"$info_min_time$","latest_offset":"$info_max_time$"}]
action.notable.param.rule_description = $user$ sent $request_count$ requests ($mb_out$ MB) to the $provider$ API ($ai_domain_list$) from $src$ between $firstTime$ and $lastTime$.
action.notable.param.rule_title = HDSI AI Example API Access ($user$ to $provider$)
action.notable.param.security_domain = network
action.notable.param.severity = low
action.notable.param.verbose = 0
alert.digest_mode = 1
action.risk = 1
action.risk.param._risk = [{"risk_object_field":"user","risk_object_type":"user","risk_score":20},{"risk_object_field":"src","risk_object_type":"system","risk_score":20}]
action.risk.param._risk_message = $user$ sent $request_count$ requests ($mb_out$ MB) to the $provider$ API ($ai_domain_list$) from $src$, identity multiplier $risk_multiplier$.
action.risk.param._risk_score = 0
action.risk.param.verbose = 0
alert.managedBy =
alert.suppress = 1
alert.suppress.fields = user,src
alert.suppress.period = 86400s
alert.track = 1
allow_skew = 5m
counttype = number of events
cron_schedule = 13 * * * *
description = v1.1.0 Example: a user calling a public model API (OpenAI, Anthropic, Gemini, Mistral, DeepSeek, Groq, Perplexity) through the web proxy at least 5 times in an hour, outside sanctioned use. Scores the user and source host by provider weight and identity sensitivity. Risk only, no notable.
disabled = 0
dispatch.earliest_time = -65m@m
dispatch.latest_time = -5m@m
dispatch.rt_backfill = 1
dispatch.ttl = 2p
enableSched = 1
realtime_schedule = 0
relation = greater than
quantity = 0
request.ui_dispatch_app = SplunkEnterpriseSecuritySuite
schedule_window = auto
search = | tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count sum(Web.bytes_out) as bytes_out min(_time) as firstTime max(_time) as lastTime from datamodel=Web where `hdsi_ai_example_api_access_scope` NOT Web.user IN ("unknown","-") `hdsi_ai_example_api_access_filter` by Web.user Web.src Web.url_domain Web.site \
	| rename Web.* as * \
	| eval ai_domain=lower(coalesce(nullif(url_domain,"unknown"),nullif(site,"unknown"))), src=nullif(src,"unknown") \
	| `ai_domains_filter` \
	| where usage_type="api" AND ai_traffic_class!="background" \
	| stats sum(count) as request_count sum(bytes_out) as bytes_out values(ai_domain) as ai_domains max(severity_weight) as severity_weight min(firstTime) as firstTime max(lastTime) as lastTime by user src provider \
	| where request_count>=`hdsi_ai_example_api_access_min_requests` \
	| `ai_unsanctioned_filter(user,src,provider)` \
	| `ai_risk_multiplier` \
	| eval severity_weight=coalesce(tonumber(severity_weight),1.0), base_score=round(20*severity_weight), risk_score=min(60,max(5,round(base_score*coalesce(risk_multiplier,1)))) \
	| eval mb_out=round(bytes_out/1024/1024,2), ai_domain_list=mvjoin(mvindex(ai_domains,0,4),", ") \
	| convert ctime(firstTime) ctime(lastTime) \
	| eval ai_activity="example_api_access", detection_id="hdsi_ai_example_api_access", mitre_attack="T1588.007", ai_kill_chain_phase="execution" \
	| `hdsi_ai_example_api_access_customizations` \
	| `hdsi_ai_example_api_access_risk_score`
```

The example shows the pattern only. A real detection still needs the checks in [CONTRIBUTING.md](CONTRIBUTING.md#pull-request-checklist): placeholder-user handling, shared-source guards and a measured threshold.
