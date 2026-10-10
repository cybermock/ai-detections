## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds **delivered inbound email that links to a site published with an AI site or app builder**: Lovable (`*.lovable.app`), Vercel v0 previews (`*.vusercontent.net`), Gamma documents (`gamma.app/docs/...`, `*.gamma.site`), Base44, Bolt, Create, Replit, Framer and Figma Sites. It also catches Vercel and Netlify hosts when the link has lure wording, points to a payload file, or the gateway hard-blocked the same site for other recipients (non-bulk senders only). Attackers use these builders to produce convincing credential-harvesting pages in minutes, on trusted domains that most URL reputation engines do not block. Public reporting from 2025 covers Lovable, v0 and Gamma phishing campaigns. Each run creates risk on the **internal recipient** (`user`, the recipient address). The score rises with lure wording, a payload link, a free-mail sender, copies of the same site that the gateway blocked, or a visit by the recipient to the host. The rule creates no notable.

**Why v1.1 replaces v1.0.** v1.0 correlated "the user made ≥5 AI web requests" with "the user sent ≥10 emails" in a 10-minute window. That logic had two problems:
- **The join never matched.** v1.0 joined `Email.src_user` (an email address) to `Web.user`. On Tenant A, 1,940 of about 2,200 AI web users were `DOMAIN\user`, so the join could not match them.
- **With the join fixed, it measured normal office work.** Over 2 hours on Tenant A there were 60 user-hours with both AI use and external email. The busiest of them had 9 external recipients, and the p99 across all senders was 7 recipients per hour. No AI-plus-mass-mailing pattern exists to detect. Mass-mailing compromised accounts are covered by the high-volume-email-to-non-corporate-domains package.

v1.1 keeps the purpose, AI-generated phishing, but uses the observable that the data actually supports: the phishing link.

### Prerequisites
- **CIM `Email.All_Email`, accelerated, with `url` and `recipient` populated.** The email gateway must put URLs found in messages into `Email.url`. For example, the Proofpoint on Demand `pps_messagelog` sourcetype does this. Exchange message tracking and Proofpoint TAP SIEM events (as mapped on Tenant C) do not, and Tenant B has no Email data. Without `url` the rule runs cleanly and returns nothing. A `data_prereqs` search in `package.yml` checks for `url`.
- `Email.action` must say whether each copy was delivered or blocked. Only `..._delivered_actions` (`delivered`, `allowed`) can create risk. `..._blocked_actions` feeds the "stopped for other recipients" signal. Discards (Proofpoint `deleted`) are ignored by default; `..._discard_actions` is an opt-in (see Limitations).
- **A way to tell internal recipients and senders from external ones.** The gateway logs outbound mail as `delivered` too (on Tenant A, about 45% of delivered events went to about 22,000 external domains), so the rule only scores recipients it can place inside the organisation. A recipient is internal when any of these is true:
  1. The address resolves in ES `identity_lookup_expanded` (true for most mailboxes on Tenants A to C; Tenant D's identity list holds only 24 records).
  2. The domain is in `cim_corporate_email_domains.csv` (Splunk_SA_CIM). Tenants B and D still hold only the CIM example row.
  3. The domain is one of the tenant mail domains inferred from the last 24 h of Email data by `..._internal_domains`. This needs `Email.recipient_domain` and `Email.src_user_domain`, and is the only path that works on Tenant D.

  Senders in a corporate or inferred domain are excluded, so a colleague sharing their own Gamma deck does not count. The second `data_prereqs` search passes when the corporate-domain lookup holds a real domain or the domain fields are populated. If none of the three paths works, the rule runs cleanly and emits nothing.
- **Optional:** `Web` data with `user` and the hostname in `url_domain` or `site`, from an egress proxy or NGFW URL log (the click branch). Without it, the +20 "visited" signal never fires and nothing else changes. Web data whose `site` holds SSE app names rather than hostnames (Tenant C) contributes nothing.
- Common package `hdsi_ai_rba_common`: `ai_risk_multiplier` (identity `bunit` sensitivity × 1.25 for privileged identities, capped at 2.0). The rule does not use `ai_domains_filter` or `ai_unsanctioned_filter`. These are inbound links from third parties, and the provider lookup intentionally does not list user-published builder hosts such as `*.lovable.app`.

### How it works
- `tstats` over `Email.All_Email` keeps only rows whose `url` matches `..._url_prefilter` (cheap wildcards), grouped by `recipient`, `src_user`, `url` and `action`.
- `url_host` and `url_path` are parsed: lowercased, scheme/userinfo/port stripped, leading `www.` removed. `..._platform` classifies the link exactly:
  - `ai_builder`: hosts that only serve builder-published content.
  - `generic`: `*.vercel.app` and `*.netlify.app`. These count only with lure wording, a payload file, or blocked copies for other recipients from a non-bulk sender (see below).
  - Builder home pages (`lovable.dev`, `v0.app`, `bolt.new`, the `gamma.app` root) are deliberately not matched.
- Static assets are dropped by `..._static_path_regex`: images, stylesheets and fonts by extension, plus extension-less asset paths such as Lovable `/__l5e/assets-v1/<id>` and Next.js/Astro static paths. Hosts in `..._allowed_hosts` are dropped.
- Per link (host + path):
  - `lure`: `..._lure_regex` matches the host or the path (credential, document/e-signature, finance/HR, update/notice and brand words). The Gamma `/docs/` prefix is ignored. Newsletter housekeeping links (unsubscribe, preference centre, subscription management, `..._benign_link_regex`) never count as lure, so `update-preferences` is not a lure.
  - `payload`: the path ends in an archive, script, disk image or executable extension (`..._payload_regex`, including `.js` and `.vbs`).
  - `other_stopped`: other recipients whose copy of a link to the **same site** was stopped. A copy is stopped when its action is in `..._blocked_actions`. If you opt in to `..._discard_actions`, a discarded copy also counts unless that recipient has a delivered copy of the same link. The site is the host, because builder and hosting subdomains belong to one publisher; for the shared `gamma.app` host it is host + path. The recipient's own stopped copy is not counted.
  - `link_bulk`: any sender of that link matched `..._bulk_sender_regex` (no-reply/bounce/marketing mailboxes, SES VERP addresses, ESP sending subdomains such as `em-1234.` and ESP domains including Mailchimp, SendGrid, SES, HubSpot and Brevo/Sendinblue).
  - `freemail_sender`: the sender matched `..._freemail_regex`.
- **Eligibility:** a delivered link is kept when it is on an `ai_builder` host, or a `generic` host with lure wording, a payload file, or blocked copies for other recipients **and** no bulk/ESP sender. A partly blocked marketing send is therefore not enough on its own.
- Only delivered rows from external senders to internal recipients are kept.
- **Click branch:** `tstats` over `Web` for the same hosts in `url_domain` or `site` (`fillnull_value="unknown"`, because a null `by` field drops the row), by `user`, `url_domain` and `site`; the host is `url_domain`, or `site` when `url_domain` is empty. `DOMAIN\` is stripped from the user, which is then resolved through `identity_lookup_expanded`. Email and web rows are joined on the identity record and the host. `clicked=1` when the recipient's web traffic reached the emailed host in the same window.
- **Scoring (per link):**
  - Base: 25 for `ai_builder`, 20 for `generic`.
  - +15 lure wording, +20 payload file, +10 free-mail sender, +15 stopped for other recipients, +20 clicked.
  - −15 bulk/ESP link.
  - Links below `..._min_score` (20) are dropped.
- **Per recipient:** the top-scoring link sets `base_score`, `url_host`, `top_link` and the evidence string, so the drilldown and the message describe the link that produced the score. `url_hosts`/`url_host_list` list only qualifying links. `risk_score = min(60, round(base_score × risk_multiplier))`. The `_risk` literal fallback is 25 on `user`.
- **Risk object:** `user` = the recipient address. It is never `unknown`, because `recipient="unknown"` is excluded in `tstats`. ES identity correlation maps the address to the identity.
- **Cadence:** hourly at :12 over `-65m@m` to `-5m@m`, suppressed 24 h per `user`. One user receiving several builder links in a day produces one risk event. `..._internal_domains` looks back 24 h on its own (`earliest=-1445m@m`).

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_generated_phishing_indicators_filter` | `()` | Exclusions inside the Email `tstats` where clause (`All_Email.*`), e.g. a partner that legitimately sends builder links |
| `hdsi_ai_generated_phishing_indicators_url_prefilter` | 17 `All_Email.url` wildcards | Cheap prefilter. To add a builder, add the pattern here and a `case()` branch in `_platform` |
| `hdsi_ai_generated_phishing_indicators_platform` | Lovable, v0 preview, Gamma docs, Base44, Bolt, Create, Replit, Framer, Figma Sites (`ai_builder`); Vercel, Netlify (`generic`) | Exact host classification and tier |
| `hdsi_ai_generated_phishing_indicators_web_prefilter` | Same hosts on `Web.url_domain` and `Web.site` | Click-branch prefilter |
| `hdsi_ai_generated_phishing_indicators_web_filter` | `()` | Exclusions inside the Web `tstats` where clause (`Web.*`) |
| `hdsi_ai_generated_phishing_indicators_allowed_hosts` | `"__none__"` | Known-good builder hosts for this tenant (wildcards allowed), e.g. a vendor's status page |
| `hdsi_ai_generated_phishing_indicators_static_path_regex` | images, CSS, fonts; `/__l5e/`, `/_next/static/`, `/_next/image/`, `/_astro/`, `/static/media/` | Asset links dropped before scoring |
| `hdsi_ai_generated_phishing_indicators_payload_regex` | `.zip .rar .7z .iso .img .exe .msi .scr .bat .cmd .ps1 .vbs .js .wsf .hta .lnk .jar .apk .dmg .xll .one` ... | Payload link, +20 (makes a `generic` link eligible) |
| `hdsi_ai_generated_phishing_indicators_lure_regex` | login/verify/password/MFA, document/contract/agreement/proposal/sign/DocuSign, invoice/receipt/paystub/payroll/salary/bonus/benefit/W-2/tax/refund/statement, update, voicemail, Microsoft/OneDrive/SharePoint/Adobe/... | Lure wording, +15 (makes a `generic` link eligible) |
| `hdsi_ai_generated_phishing_indicators_bulk_sender_regex` | no-reply, bounce, marketing@, SES VERP, ESP subdomains (`send.`, `em-1234.` ...) and ESP domains (Mailchimp, SendGrid, SES, HubSpot, Brevo/Sendinblue ...) | Newsletter/marketing noise control, −15; a bulk link cannot qualify a `generic` host through blocked copies alone |
| `hdsi_ai_generated_phishing_indicators_benign_link_regex` | unsubscribe, preference, opt-out, subscription, email-settings, view-in-browser | Newsletter housekeeping links never count as lure |
| `hdsi_ai_generated_phishing_indicators_freemail_regex` | Gmail, Outlook/Hotmail, Yahoo, AOL, iCloud, Proton, GMX, Zoho, Yandex... | Free-mail sender, +10 |
| `hdsi_ai_generated_phishing_indicators_internal_domains` | 24 h inference from Email domain pairs | Internal mail domains (`internal_domains="\|dom1\|"`). To pin them, replace with `eval internal_domains="\|example.com\|example.org\|"` |
| `hdsi_ai_generated_phishing_indicators_min_score` | `20` | Lowest per-link score emitted (see Threshold) |
| `hdsi_ai_generated_phishing_indicators_delivered_actions` | `"delivered","allowed"` | Actions that mean the mailbox received the message |
| `hdsi_ai_generated_phishing_indicators_blocked_actions` | `"blocked","quarantined","quarantine","dropped","rejected"` | Hard gateway blocks (always count as stopped) |
| `hdsi_ai_generated_phishing_indicators_discard_actions` | `"__none__"` (off) | Opt-in: gateway discard actions that count as stopped, e.g. `"deleted","discarded","discard"`. Only enable if discard is used solely for malicious mail (see Limitations) |
| `hdsi_ai_generated_phishing_indicators_customizations` | `search *` | Post-aggregation hook (fields: `user`, `recipient`, `url_host`, `top_link`, `url_hosts`, `url_host_list`, `links`, `link_count`, `ai_platforms`, `provider`, `senders`, `sender_list`, `sender_count`, `subject`, `email_events`, `lure`, `payload`, `freemail_sender`, `link_bulk`, `other_stopped`, `clicked`, `evidence`, `base_score`, `risk_multiplier`, `risk_score`) |
| `hdsi_ai_generated_phishing_indicators_risk_score` | `search *` | Last pipe. Override `risk_score` (≤100) here |

### Threshold
`..._min_score` defaults to 20:
- It drops a plain builder link that came from a bulk/ESP sender with no other indicator (25 − 15 = 10).
- It keeps every other delivered builder link (≥25) and any generic-hosting link that qualified (≥20).
- Raising it to 35 keeps only links with a second indicator (lure, payload, free-mail sender, blocked copies or a visit). On Tenant A that would have kept 4 of the 8 recipients in the 7-day test (the three plain Gamma documents and one plain Base44 page drop out).

To choose a value, run the rule over 7 days with the time picker and look at the tier mix:

```spl
| savedsearch "Threat - HDSI AI Generated Phishing Indicators - Rule"
| stats count as recipients values(provider) as platforms by base_score evidence
| sort - base_score
```

A 7-day window correlates more loosely than the hourly schedule, so treat the result as an upper bound. To see raw builder-link volume by platform and action before enabling, run:

```spl
| tstats summariesonly=t allow_old_summaries=t count dc(All_Email.recipient) as recipients
    from datamodel=Email.All_Email where `hdsi_ai_generated_phishing_indicators_url_prefilter`
    by All_Email.action All_Email.url
| rex field=All_Email.url "^(?:[A-Za-z][A-Za-z0-9+.-]*://)?(?:[^@/?#]*@)?(?<url_host>[^/:?#\s]+)(?::\d+)?(?<url_path>/[^?#\s]*)?"
| eval url_host=replace(lower(url_host),"^www\\d*\\.",""), url_path=lower(coalesce(url_path,"/"))
| `hdsi_ai_generated_phishing_indicators_platform`
| stats sum(count) as events sum(recipients) as recipients by ai_platform All_Email.action
```

To check which domains `..._internal_domains` infers (expect your primary mail domain, not a free-mail domain):

```spl
| makeresults
| `hdsi_ai_generated_phishing_indicators_internal_domains`
| table internal_domains
```

### Known false positives / Limitations
- **Legitimate businesses build on these platforms.** Over 7 days on Tenant A, many raw hits were legitimate:
  - Tracking, unsubscribe and booking endpoints on small vendors' `*.lovable.app` apps, sent through ESPs.
  - Mailing-list digests.
  - Gamma newsletters and reports from partners or agencies.

  Plain builder links with no second indicator score 25. Put recurring partners in `..._allowed_hosts` or `..._filter`.
- **Bulk/ESP trade-off.** The −15 bulk/ESP adjustment also applies to phishing sent through an ESP (SES, SendGrid, Mailchimp and similar, or a compromised ESP account). A builder link from an ESP sender with no lure, payload, stopped copy or visit scores 10 and is not emitted. Any one of those indicators brings it back to 25 or more. If ESP-borne phish is a concern, lower `..._min_score` to 10 or trim `..._bulk_sender_regex`.
- **Proofpoint `deleted` is not a block signal by default.** In `pps_messagelog`, `action=deleted` maps from disposition `discard`, which Tenant A uses as a routine graymail/bulk disposition: about 190,000 URL-bearing events a day, mostly vendor, conference and trade-newsletter marketing (the tenant's own domain is among the top senders). An earlier draft counted `deleted` as stopped. In a 7-day test that made 9 of 18 emitted recipients depend on it, and every one checked was legitimate marketing (a medical-conference registration campaign on Netlify, a research vendor's form on Vercel, a Gamma newsletter). `..._discard_actions` therefore ships as `"__none__"`. Enable it only if your gateway discards nothing but malicious mail. Hard blocks (`..._blocked_actions`) still count, and blocked copies alone cannot qualify a `generic` link that came from a bulk/ESP sender. The malicious Vercel payload campaigns seen on Tenants A and D were never delivered, so they would not have created risk either way.
- **Legitimate vendor pages still score.** A small vendor's Lovable-built CRM sent a `/contract/<id>` page through Amazon SES and the recipient opened it: lure (+15) and visit (+20) outweigh the bulk adjustment (−15), so it scored 45. Gamma documents shared by outside organisations (newsletters, partner reports) score 25 with no other indicator. Use `..._allowed_hosts` for recurring vendors, or raise `..._min_score` to 35.
- **Spoofed internal senders are excluded.** Senders in a corporate or inferred internal domain are dropped, so a phish that spoofs the organisation's own domain in `src_user` is not scored here (DMARC enforcement and the gateway's spoofing controls cover that case).
- **Subsearch time limits.** `..._internal_domains` and the click branch are `append` subsearches, so they are subject to the subsearch time limit (60 s by default) and result limits. If the domain inference times out or returns nothing, `internal_domains` becomes `|__none__|` and only the identity and CIM-lookup paths can mark a recipient as internal: a tenant that relies on inference alone (Tenant D) then emits nothing, without a warning. If the click branch times out, `clicked` is undercounted. In the hourly window both finish in seconds on the validation tenants; in a 7-day backtest on Tenant A one subsearch hit the 60 s limit. Pin `internal_domains` (see the macro) on tenants that depend on inference.
- **Domain inference picks the primary domain.** `..._internal_domains` keeps domains with two-way traffic to at least 10 other domains and at least a quarter of the busiest domain's. On Tenants A and D it selected exactly one domain. Secondary corporate domains come from the CIM lookup or the identity list; pin them in the macro if neither has them.
- **Rewritten URLs.** If the gateway records only the rewritten link (`urldefense.com`, Safe Links), the builder host is not visible and the row is not matched. Proofpoint `pps_messagelog` records the original URL.
- **Only URLs the gateway extracts.** Links inside attachments (PDF, HTML, QR codes) are not in `Email.url` and are missed.
- **Click attribution covers the same hour only.** It needs `Web.user` that resolves to the same identity record as the recipient address, and the visit must fall in the same 60-minute window as the delivery (it may also come before it). A click in a later hour adds nothing, and the recipient is suppressed for 24 h after the first event. Use the "View who visited $url_host$" drilldown at triage to check later visits.
- **Per-recipient path tokens.** Campaigns that put a unique token in each link (`/sign/<uuid>`) are grouped by site (host) for the stopped-copies signal, so they are still counted together. On `gamma.app` the grouping is host + path, so per-recipient Gamma links are not.
- **No content analysis.** The rule cannot tell that a page or message was written by AI. It flags the hosting channel that AI builders create, which is what is observable in CIM data.

### Validation
Read-only live tests on 4 production ES tenants, 2026-10-09.

| Tenant | Email data / `url` populated | Internal-recipient path | Web click data | v1.0 (before) | v1.1 parse | v1.1 rows | Notes |
|---|---|---|---|---|---|---|---|
| A | Yes, ~135M events/day; `url` from Proofpoint message log | Identity + CIM lookup + 1 inferred domain | Yes (NGFW URL log, `DOMAIN\user`) | 200, 0 rows; web drilldown 263 s | OK | 0 (4 h) / 8 (7 d) | 7-day run (116 s): 2 recipients of free-mail mail linking to a Base44 page with e-signature wording (50, likely phishing); 1 free-mail Base44 page (35); 1 legitimate vendor CRM `/contract/` page on Lovable sent through SES that the recipient opened (45, false positive); 3 Gamma documents from outside organisations and 1 plain Base44 page (25, low-value). No Vercel/Netlify rows: the 9 generic-hosting rows of the earlier draft depended on `deleted` and every one checked was legitimate marketing (see Limitations). Over 7 days builder-link copies were 828 deleted, 154 delivered, 17 blocked. 4-hour run 13 s |
| B | No Email data | n/a | Inbound load-balancer/WAF only | 200, 0 rows; web drilldown 303 s | OK | 0 (4 h) | Nothing to detect without email |
| C | Yes (message tracking + TAP SIEM); `url` 0% | Identity + CIM lookup (no domain fields to infer from) | SSE app names only (`site`), no `url_domain` | 200, 0 rows | OK | 0 (4 h) | Map `url` from the email gateway to enable |
| D | Yes; `url` from Proofpoint message log | Inferred domain only (24 identities, CIM example row) | None | 200, 0 rows | OK | 0 (4 h) / 0 (7 d) | Over 7 days builder-link copies were 71 deleted, 48 blocked, 3 delivered (2 recipients); the rule emits nothing from the delivered copies. The blocked campaigns (payload links on vercel.app) were never delivered, so there is nothing to score |

Other checks:
- All three drilldowns parse on all four tenants.
- Synthetic examples: `/invoice`, `/new-update`, `/download/setup.zip`, `/tool.vbs` and `/sign` score as lure and/or payload; `update-preferences` and `/unsubscribe` do not count as lure; a Lovable `/__l5e/assets-v1/…` path is dropped as a static asset; words that only contain a short lure word (`assign`, `syntax`, `preview`) do not match. Brevo/Sendinblue (`*.sender-sib.com`) and SendGrid `em-1234.` sending subdomains are recognised as bulk senders.
- With the fixed join, v1.0's thresholds (≥5 AI requests and ≥10 emails per user) matched 2 user-hours in 2 hours on Tenant A, both ordinary office activity.

### Deployment
The package ships with `enable_alerting: false`. Before enablement:
- Confirm that `Email.url` is populated with original (not rewritten) URLs.
- Confirm that internal recipients can be identified: run the `..._internal_domains` check above, or populate `cim_corporate_email_domains.csv`.
- Run the 7-day tier query above.
- Allow-list recurring legitimate builder hosts.

The rule is risk-only. It emits at most one modest risk event (20 to 60) per recipient per day, and the AI RBA risk aggregators decide on notables. Enabling it must be a separately approved change.
