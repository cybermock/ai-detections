## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds **users and hosts that use hosted voice cloning and voice conversion services**: ElevenLabs, PlayHT, Resemble AI, WellSaid Labs, Murf AI, LOVO AI, Coqui, FakeYou, Uberduck, Voicemod, HeyGen, Fish Audio and Cartesia. A cloned voice is the raw material for CEO-voice fraud, vishing and fake help-desk calls. The same services are also bought for legitimate narration and training content, so using one is a context signal, not an incident. Evidence comes from Web (proxy, firewall URL or SSE logs) and DNS. In-app voice cloning or conversion requests score highest. Voice Lab and voice design use come next, then repeated signed-in app use. API use, site plus API use and repeated marketing or product page visits score low. Docs, help, blog and pricing pages, sign-up and sign-in pages, and single visits do not qualify. The rule runs once a day and creates risk on `user` and/or `src` (system), between 3 and 60. It creates no notable.

v1.0 returned 0 rows on all four validation tenants. Its design had these defects:

- It split `tstats` by both `Web.url_domain` and `Web.site` without `fillnull_value`. Rows missing either field were dropped, and most proxies fill only one of them. That meant Tenant A (`site` empty) and Tenant C (`url_domain` empty) could never match.
- It had no DNS path, although DNS is the only voice-service evidence on Tenant B and most of it on Tenant C.
- It scored every request to any provider host. Most of that volume was not voice cloning: Deepgram speech-to-text inside dictation and meeting tools, the Speechify reading extension, ElevenLabs voice-agent widgets and audio players embedded in third-party websites, and affiliate links.
- It set `user="unknown"` and `src="unknown"`, so those placeholders collected risk. It ran every 5 minutes with a 1-hour suppression, which could create 24 or more events a day for one person. Its MITRE technique was T1588.005 (Exploits); the correct technique is T1588.007 (Obtain Capabilities: Artificial Intelligence).

### Prerequisites
| Data | Fields used | If absent |
|---|---|---|
| `Web` data model (accelerated) from an **egress** proxy, firewall URL log or SSE/CASB | `user`, `src`, `url_domain` and/or `site`, `url`, `action` | The Web path returns nothing. Inbound server logs (load balancer, WAF, IIS) never resolve to a voice provider |
| URL paths in `Web.url` (decrypting proxy, enterprise browser, SSE) | `url` | The voice-clone (35) and Voice Lab (25) classes never fire, and marketing, sign-up and app pages on the main domain cannot be told apart. Host-only logs (TLS SNI) still give app-host, API and site evidence |
| `Web.bytes_out` / `Web.bytes_in`, `Web.http_method` | bytes, method | Only for the upload bonus (+15) on voice-clone routes. Without byte fields it never fires. `http_method` is optional (rows without it are allowed) |
| `Network_Resolution` data model (accelerated) with client-facing DNS logs | `DNS.src`, `DNS.query` | The DNS path returns nothing. DNS rows are host-only (no user) |

- `site` may be a hostname or an SSE application name (Netskope `site` = "WellSaid Labs"). When `url_domain` is empty, the rule sets `ai_input_type=app` so the provider resolves through `ai_provider_apps`. The request itself is still classified by the host and path in `Web.url`.
- DNS `src` must be the **client**. The shared-source guard removes resolvers, forwarders and NAT egress addresses (see Threshold).
- **Common package** (`hdsi_ai_rba_common`, required): `ai_domains_filter` (the `ai_provider_domains` and `ai_provider_apps` lookups, including `traffic_class`), `ai_unsanctioned_filter(3)` (`ai_sanctioned_entities` approvals) and `ai_risk_multiplier` (ES `identity_lookup_expanded` `bunit` with `ai_department_sensitivity`).
- ES `identity_lookup_expanded` and `asset_lookup_by_str` supply `bunit` for group approvals. Users without an identity keep a multiplier of 1.0.

### How it works
- **Collection:** runs daily over `-1d@d` to `@d`, using three `tstats` searches:
  1. `Web`, pre-filtered by `..._web_scope` (the providers' domains and SSE application names), split by `sourcetype`, `user`, `src`, `url_domain`, `site` and `url`, with `fillnull_value="unknown"`.
  2. An appended `Network_Resolution` search, pre-filtered by `..._dns_scope`, split into 1-minute buckets by `src` and `query`. The DNS count is the number of **distinct minutes** in which the client looked the name up (a "lookup-minute"). Clients repeat the same lookup within a minute and some logs record both query and response; on Tenants A to C raw lookups were 1.7 to 1.9 times the lookup-minutes. Without this, one visit counted as two app lookups.
  3. An appended shared-source guard: DNS clients that resolved at least `..._shared_src_names` distinct names that day.
- **Provider resolution:** `ai_domain` = `url_domain`, else `site`, else the DNS `query`, resolved by `ai_domains_filter`. Only providers in `..._providers` are kept. Placeholder users and sources are dropped. Public source addresses (inbound traffic), shared DNS clients and `..._untrusted_src` addresses are never used as the `src` risk object. A user-attributed row keeps its user without `src`; a row with neither a user nor a usable `src` is dropped.
- **Request host:** `class_host` is the host from `Web.url` when the log carries one, otherwise `ai_domain` (with port, trailing dot and `www.` removed). Classification uses `class_host`, so an SSE application-name match on the marketing homepage (`www.wellsaid.io/`) is site browsing, not signed-in use.
- **Evidence classes** (first match wins, per request; background is checked first):
  - **background:** registry rows with `traffic_class=background`, embedded players, voice-agent widgets, share and embed links, affiliate links, help, docs, blog and pricing pages, static assets, CDNs and analytics (`..._background`). Listed, never counted.
  - **clone:** an API call or in-app page that creates or applies a cloned or converted voice, where a real voice is the input (`..._clone_evidence`): `/v1/voices/add`, `/v1/voices/pvc`, `/v1/speech-to-speech`, PlayHT `/api/v2/cloned-voices`, `/app/speech-synthesis/speech-to-speech`. A clone path only counts on an API route, under `/app/` or `/studio/`, or on an app host, so public product pages such as `elevenlabs.io/voice-cloning` or `murf.ai/voice-changer` do not.
  - **voicelab:** voice management and voice design (`..._voicelab_evidence`): `/app/voice-lab`, `/app/voice-design` and the voice design API `/v1/text-to-voice`, `/v1/voice-generation`. Voice design makes a synthetic voice from a text prompt, and the Voice Lab is also where users pick stock voices, so this class sits below clone.
  - **app:** application and studio hosts, and `/app/`, `/studio/` or `/dashboard/` paths (`..._app_evidence`). Account pages (`/app/sign-up`, `/app/sign-in`, `/app/onboarding`, `/auth/`, `/__/auth/`) and sign-in hosts (`auth.`, `login.`) are not app use and fall to browse.
  - **api:** the providers' API hosts, including regional ones such as `api.us.elevenlabs.io` (`..._api_evidence`).
  - **browse:** every other provider host or page: the marketing site, product pages such as `/voice-cloning` or `/text-to-speech`, and sign-up or sign-in pages.
- **Attribution:** DNS rows from a host that had exactly one Web user that day are attributed to that user. The entity is the user when known, otherwise the host.
- **Qualification per entity and provider per day** (Web: requests; DNS: lookup-minutes):

  | Evidence | Base | Evidence text |
  |---|---|---|
  | Any clone request | 35 | voice cloning or conversion request |
  | Any Voice Lab or voice design request | 25 | Voice Lab or voice design use |
  | `..._min_app_events` (2) or more app requests | 20 | signed-in app use |
  | `..._min_api_events` (10) or more API requests | 12 | sustained API use |
  | API plus site requests, at least `..._min_browse_events` (5) together | 12 | site and API use |
  | `..._min_browse_events` (5) or more site requests | 8 | repeated site visits |

  Anything less is dropped. API evidence scores only 12 in every combination because, on host-only logs, a widget or player embedded in another website looks the same as the provider's own app calling its API.
- **Approvals:** `ai_unsanctioned_filter(user,src,provider)` removes approvals by user, host, `bunit` (the rule passes the user's identity `bunit`, else the host's asset `bunit`) or organisation-wide (`*|<provider>`).
- **Scoring:**
  - Provider score = base × provider `severity_weight` (0.5 for Voicemod up to 1.0 for API hosts), × 0.5 if every Web request was blocked.
  - Entity `base_score` = the highest provider score, + 5 per extra provider, + 15 if at least `..._upload_mb` (1 MB) was sent to voice-clone routes.
  - The upload is the client-to-server byte count of clone-class rows whose `http_method` includes POST, PUT or PATCH or is not logged. The client-to-server side is `Web.bytes_out`, or `Web.bytes_in` for sourcetypes matched by `..._bytes_reversed` (ships as Netskope). App, Voice Lab and dashboard page loads never count, so heavy ordinary browsing cannot reach the bonus.
  - `risk_score = min(60, max(3, round(base_score × risk_multiplier)))`, where `risk_multiplier` is 1.0 to 2.0. `risk_score` applies to both risk objects. The literal `_risk` fallbacks are 20 and 20.
- **Suppression:** 23 hours per `user,src` (`82800s`). One row per entity per day.
- **Output:** the risk message names the user and host, the providers and their evidence, and a request summary (for example "17 Voice Lab, 11 app, 2 site requests or lookup-minutes"). `mb_uploaded` is set only when the source has byte fields. `src_hosts` (up to 10 trusted hosts) feeds the DNS drilldown, so it also works on user rows that have no single `src`.

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_voice_cloning_api_access_filter` | `()` | Exclusions inside the Web `tstats` where clause (`Web.*` names), for example an approved media team's subnet |
| `hdsi_ai_voice_cloning_api_access_dns_filter` | `()` | Exclusions inside both DNS `tstats` where clauses (`DNS.*` names), for example resolvers below the guard threshold |
| `hdsi_ai_voice_cloning_api_access_providers` | 13 providers | Provider names that are scored. Deepgram, Speechify, Synthesia and Descript are deliberately absent (see Known false positives) |
| `hdsi_ai_voice_cloning_api_access_web_scope` | domains and app names | Web pre-filter. Keep it in step with `..._providers` |
| `hdsi_ai_voice_cloning_api_access_dns_scope` | domains | DNS pre-filter. Keep it in step with `..._providers` |
| `hdsi_ai_voice_cloning_api_access_background` | regex condition | Hosts and paths that never count. Checked first |
| `hdsi_ai_voice_cloning_api_access_clone_evidence` | regex condition | API routes and in-app paths that clone or convert a real voice (base 35) |
| `hdsi_ai_voice_cloning_api_access_voicelab_evidence` | regex condition | Voice management and voice design pages and API routes (base 25) |
| `hdsi_ai_voice_cloning_api_access_app_evidence` | regex condition | App and studio hosts, `/app/` or `/dashboard/` paths, minus account pages |
| `hdsi_ai_voice_cloning_api_access_api_evidence` | regex condition | API hosts |
| `hdsi_ai_voice_cloning_api_access_min_app_events` | `2` | App requests (DNS: lookup-minutes) per entity per provider per day for signed-in app use |
| `hdsi_ai_voice_cloning_api_access_min_api_events` | `10` | API requests per entity per provider per day that qualify without a site visit (see Threshold) |
| `hdsi_ai_voice_cloning_api_access_min_browse_events` | `5` | Site requests that qualify at base 8. Also the minimum for site plus API use (base 12) |
| `hdsi_ai_voice_cloning_api_access_upload_mb` | `1` | MB sent to voice-clone routes in a day that adds 15 to the base score |
| `hdsi_ai_voice_cloning_api_access_bytes_reversed` | `match(sourcetype,"^netskope:")` | Sourcetypes whose `Web.bytes_out` holds server-to-client bytes (see Threshold) |
| `hdsi_ai_voice_cloning_api_access_shared_src_names` | `10000` | Distinct DNS names per client per day above which the client is treated as shared infrastructure |
| `hdsi_ai_voice_cloning_api_access_untrusted_src` | `false()` | Addresses that are not a stable host identity, for example a VPN pool: `cidrmatch("100.64.0.0/10",src)` |
| `hdsi_ai_voice_cloning_api_access_customizations` | `search *` | Post-scoring hook (`risk_entity`, `user`, `src`, `src_hosts`, `provider_list`, `evidence_list`, `request_summary`, `clone_events`, `voicelab_events`, `app_events`, `api_events`, `browse_events`, `mb_uploaded`, `ai_domain_list`, `evidence_source_list`, `bunit`, `base_score`, `risk_multiplier`, `risk_score`) |
| `hdsi_ai_voice_cloning_api_access_risk_score` | `search *` | Last pipe. Override `risk_score` (1 to 100) here |

Sanctioned use goes in `ai_sanctioned_entities` in the common package, for example a training team licensed for WellSaid Labs or ElevenLabs. The key is `<user, src or bunit>|<provider>` (`training|wellsaid labs`), `<entity>|*`, or `*|<provider>` for an organisation-wide licence (`*|wellsaid labs`). The provider string is the one in `..._providers`, lowercased.

To add a provider, it must first exist in `ai_provider_domains` (or `ai_provider_apps`) in the common package. Then add its provider name to `..._providers`, its domain to `..._web_scope` and `..._dns_scope`, and its SSE application name to `..._web_scope`.

### Threshold
**`..._min_api_events` (10).** API hosts are called by the providers' own web apps and SDKs, and also by voice agents and audio players embedded in other websites. Signed-in use almost always reaches the provider's app too, and that qualifies on its own at 20. Derive a tenant value from API-only Web entity-days over a week (this splits by URL, so expect a few minutes on a large proxy):

```spl
| tstats summariesonly=t allow_old_summaries=t fillnull_value="unknown" count from datamodel=Web
    where `hdsi_ai_voice_cloning_api_access_web_scope` by _time span=1d Web.user Web.src Web.url_domain Web.site Web.url
| rename Web.* as *
| eval ai_domain=lower(coalesce(nullif(url_domain,"unknown"),nullif(site,"unknown"))), ai_input_type=if(isnull(nullif(url_domain,"unknown")),"app","host"), url_host=if(url!="unknown" AND match(url,"^([A-Za-z][A-Za-z0-9+.-]*://)?[^/?#]+"),lower(replace(url,"^([A-Za-z][A-Za-z0-9+.-]*://)?([^/?#]+).*$","\2")),""), url_path=if(url="unknown","",lower(replace(replace(url,"^([A-Za-z][A-Za-z0-9+.-]*://)?[^/?#]+",""),"[?#].*$","")))
| `ai_domains_filter`
| search provider IN (`hdsi_ai_voice_cloning_api_access_providers`)
| eval class_host=replace(replace(replace(coalesce(nullif(url_host,""),ai_domain),":\d+$",""),"\.+$",""),"^www\d*\.","")
| where NOT `hdsi_ai_voice_cloning_api_access_background`
| eval entity=if(user="unknown",src,user), is_api=if(`hdsi_ai_voice_cloning_api_access_api_evidence`,1,0)
| stats sum(eval(is_api*count)) as api sum(eval((1-is_api)*count)) as other by entity provider _time
| where api>0 AND other=0
| stats count as entity_days perc50(api) as p50 perc90(api) as p90 perc99(api) as p99 max(api) as max
```

On Tenant A over 7 days (2026-10-02 to 2026-10-08), this SPL returned 154 API-only entity-days: p50 1, p90 about 10, p99 about 64, maximum 152. So 10 keeps roughly the top 10%. Those rows are still ambiguous (see Known false positives), which is why they score 12. Tenants B and C had no API-only Web entity-days. Set the threshold a little above p90 if API-only rows on your network are mostly widgets. Lower it if your developers call these APIs directly.

**`..._shared_src_names` (10,000).** The derivation is the same as for `hdsi_ai_dns_queries_to_ai_domains`. In validation, ordinary clients resolved fewer than about 3,000 distinct names a day, while resolvers and egress addresses resolved 11,000 to 380,000. On Tenant A, 108 DNS clients were above 10,000 in one day. Check your resolvers over one full day:

```spl
| tstats summariesonly=t allow_old_summaries=t dc(DNS.query) as names from datamodel=Network_Resolution by DNS.src
| where names>=3000 | sort - names
```

**`..._bytes_reversed` (Netskope).** Downloads dominate web traffic, so for a correctly mapped source `bytes_out` is much smaller than `bytes_in`. Run this over one hour; any sourcetype with a ratio well above 1 stores server-to-client bytes in `bytes_out` and belongs in the macro:

```spl
| tstats summariesonly=t allow_old_summaries=t sum(Web.bytes_out) as bytes_out sum(Web.bytes_in) as bytes_in from datamodel=Web by sourcetype
| where bytes_in>0 | eval out_in_ratio=round(bytes_out/bytes_in,2) | sort - out_in_ratio
```

On Tenant C, `netskope:connection` had a ratio of about 4.4 across all traffic and about 41 for voice-provider traffic over 7 days.

### Known false positives / Limitations
- **Legitimate narration and training content.** WellSaid Labs, ElevenLabs and HeyGen are bought for e-learning, marketing and accessibility. On Tenant C, every qualifying row was WellSaid Labs studio use. Approve licensed teams by `bunit` or user, or the whole organisation with `*|<provider>`, in `ai_sanctioned_entities`.
- **Voice Lab and voice design are not proof of cloning.** `/app/voice-lab` was the only cloning-related path seen in validation. It is also where users pick stock voices, and voice design creates a synthetic voice from a text prompt, so both score 25, not 35. Only API routes and in-app pages that take a real voice as input score 35. None appeared in the validation window.
- **Marketing and product pages do count, at the lowest tier.** Pages such as `elevenlabs.io/voice-cloning`, `elevenlabs.io/text-to-speech`, `play.ht/voice-cloning/` and `murf.ai/voice-changer` are public. They are site browsing: 5 or more requests score 8, and together with API requests (a product page's demo calls the API) 12. Docs, help, blog and pricing pages never count.
- **Account pages.** Sign-up, sign-in and onboarding pages (`/app/sign-up`, `/app/onboarding`, `/__/auth/handler`) and sign-in hosts are site browsing, not signed-in use. On Tenant A they appeared 1 to 4 times each in 7 days.
- **Embedded voice agents and audio players.** Third-party websites embed ElevenLabs voice agents (`*.rtc.elevenlabs.io`, `/v1/convai/`) and article audio players (`elevenlabs.io/player/`, served from the main domain), as well as PlayHT players (`a.`, `media.`, `static.play.ht`). On Tenant A, `turn.rtc` and `livekit.rtc` were each reached by about 50 hosts a week. On decrypted URLs, `..._background` removes them. On **host-only (SNI) logs** a player page that loads `elevenlabs.io` and `api.elevenlabs.io` looks like site plus API use, and a widget that polls the API 10 or more times looks like sustained API use. Both score 12 (6 when blocked). On Tenant A's busiest days most rows were of this kind: host-only `api.elevenlabs.io` traffic of 10 to 19 requests, usually in a 1 to 2 hour burst on a single day. Treat them as low-weight context; the score keeps them from driving risk on their own. List VPN or guest ranges in `..._untrusted_src` if host risk there is not useful.
- **Upload bonus.** The bonus needs decrypted voice-clone routes plus byte fields, so it is rare. A source whose byte direction is wrong and not listed in `..._bytes_reversed` would count the response size instead of the upload; check it with the Byte direction SPL. PAN-OS URL logs and DNS carry no bytes. No clone-route rows appeared in the validation window, so the bonus did not fire anywhere.
- **SSE application names.** Netskope labels the provider's marketing site with the same application name as the studio. The rule classifies by the host and path in `Web.url`, so a homepage visit is browsing. Application-name rows with no URL fall to browsing.
- **Single visits.** One visit to an app host does not qualify on its own, even when the same visit also looks up the provider's API, sign-in and site hosts: a HeyGen visit on Tenant B with 1 app, 1 API and 3 site lookups in one minute is dropped. Signed-in app use needs `..._min_app_events` (2) app requests or lookup-minutes.
- **Providers removed from scope.** Deepgram (speech-to-text) was the largest source on Tenant A, with about 15,000 requests from 31 users and 91 hosts in 7 days. It is embedded in dictation and meeting tools and does not clone voices. Speechify is a text-to-speech reading tool, often an accessibility accommodation, and its browser extension made most of the requests. Synthesia is enterprise avatar video, reached by 173 hosts a week on Tenant B. Descript is a general audio and video editor whose voice cloning is one feature. Add any of them back to `..._providers` only as a deliberate choice.
- **Host-only risk.** All DNS rows are host-only, and so are most firewall URL rows on Tenant A (User-ID gaps). Those rows raise system risk on the source address, which changes often on VPN and home-network ranges. List such ranges in `..._untrusted_src` to stop scoring them. User-attributed rows are kept.
- **DNS-only tenants.** DNS shows neither paths nor bytes. A host qualifies from DNS only through app or studio lookups in 2 or more distinct minutes (20 × weight), 10 or more API lookup-minutes, API plus site lookup-minutes adding up to 5 (12 × weight), or 5 or more site lookup-minutes (8 × weight). Browser DNS caching keeps lookup-minutes low, so heavy use can look modest.
- **Where paths exist.** Paths were present in the enterprise-browser audit logs on Tenant A, in some Tenant A firewall URL rows, and in the SSE connection logs on Tenant C (`Web.url` carries the full studio path). DNS and most firewall SNI rows carry none. `Web.http_method` was empty or `GET`/`CONNECT` on every in-scope source, so the method gate on the upload bonus currently admits rows by "not logged".
- **Provider coverage.** MiniMax audio is not scored, because the MiniMax provider string also covers its chat and video products. PAN-OS App-ID names such as `elevenlabs-base` are not used, because this rule reads `Web` and `Network_Resolution`, not `Network_Traffic`.
- **Cost.** On the largest tenant (about 1.1 billion DNS events a day), the shared-source guard scans every DNS client for the day in about 75 to 85 s. Its `append` has `maxtime=900`. If it were cut short, resolvers missing from its output could become `src` risk objects; add known resolvers to `..._dns_filter` as a backstop. End to end, the search took about 6 to 6.5 minutes on that tenant under concurrent test load, and under a minute on the other three.

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09. The search and all 3 drilldowns parse on all tenants. No FATAL or ERROR messages on any tenant.

The final build was run once over the test harness's default window for a daily rule (about the last 24 hours, ending 2026-10-09) with a 120-second job cap. The cap is below Tenant A's full runtime, so Tenant A's final figures come from the previous full runs of this rule (7 rows on 2026-10-08, 8 on 2026-10-09, about 6 to 6.5 minutes each), re-scored by hand with the final tiers. A synthetic `makeresults` test of the class macros ran on all four tenants with the expected result on each.

| Tenant | Voice-service data reality | v1.0 rows (4 h) | Final build, rows in window | Runtime | Notes |
|---|---|---|---|---|---|
| A | Firewall URL logs (mostly host-only, no bytes, about 80% without user), enterprise-browser audit logs with full URLs, network-capture DNS | 0 | Not complete within the 120 s cap (no errors). Previous full runs: 7 and 8 rows a day | about 6 to 6.5 min | Top row on 10-08: one user with 17 ElevenLabs Voice Lab requests plus app pages (25 × 0.9 = 23). The other rows are host-only: sustained ElevenLabs API use and site plus API hosts, now 12 (6 when blocked), and Voicemod desktop clients (6 to 10). DNS raw lookups were 1.75 times the lookup-minutes |
| B | Inbound load-balancer/WAF Web logs (no egress), cloud DNS security service | 0 | 1 | about 49 s | DNS, host-only: ElevenLabs site plus API hosts, 6 API and 4 site lookup-minutes over an hour (12). A HeyGen single visit (1 app, 1 API, 3 site lookups in one minute) qualified in the first run of this round at 18 and is dropped by the final app rule. Raw lookups were 1.68 times the lookup-minutes |
| C | SSE/CASB with `site` = application name and full URLs, roaming DNS service | 0 | 2 | about 34 s | Both DNS, host-only, WellSaid Labs studio lookups in 2 distinct minutes 1 to 3.5 hours apart (16). The previous build also counted repeated lookups within one minute as 2. In-scope `netskope:connection` traffic had `bytes_out` about 41 times `bytes_in` (reversed), and no `http_method` |
| D | Inbound IIS logs only, little public DNS | 0 | 0 | about 7 s | No data path. Expected silence |

Data checked over 7 days in earlier rounds: on Tenant A, ElevenLabs had about 20 named users and Deepgram 31. On Tenant B, ElevenLabs was resolved by 14 hosts and Synthesia by 173. On Tenant C, WellSaid Labs was resolved by 7 hosts and ElevenLabs by 12. Tenant D had none. The synthetic test confirmed the split. `/v1/voices/add`, `/v1/speech-to-speech`, `play.ht/app/voice-cloning` and `fish.audio/app/clone` are clone. `/v1/text-to-voice`, `/app/voice-design` and `/app/voice-lab` are Voice Lab. `/app/sign-up`, `/app/onboarding`, `/__/auth/handler`, `auth.heygen.com`, `/voice-cloning` and `/text-to-speech` are browse. `/app/speech-synthesis/text-to-speech`, `app.heygen.com` and a studio dashboard are app. `/docs/`, HeyGen `/share/`, `turn.rtc.elevenlabs.io` and registry background rows are background.

Expected daily volume at 23-hour suppression: Tenant A at most about 7 to 8 events a day (the per-minute DNS count can only lower it), mostly host-only at 6 to 12 with the occasional user row at 18 to 23; B 1 to 3 at 12 to 18; C 1 to 8 at 16 (almost all WellSaid Labs, near zero once that licence is approved); D none.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:

1. Confirm that `Web` holds egress proxy, firewall URL or SSE data, and/or that `Network_Resolution` holds client-facing DNS.
2. Load approvals for licensed voice and narration services (`<bunit>|wellsaid labs`, `<user>|elevenlabs`, or `*|wellsaid labs` for an organisation-wide licence) into `ai_sanctioned_entities`.
3. Run the resolver query and add resolvers or forwarders below the guard to `..._dns_filter`. Add VPN or guest pools to `..._untrusted_src` if host risk there is not useful. Run the Byte direction query and adjust `..._bytes_reversed`.
4. Run the search over several days and confirm the daily risk volume and run time.

The rule is risk-only (no notable). It is meant to add context to other AI-RBA and identity signals, not to stand alone. Enabling it is a separately approved change.
