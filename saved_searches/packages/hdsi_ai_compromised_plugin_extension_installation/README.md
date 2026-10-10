## Architect Notes
---
**Author:** Trevor Mock, Hurricane Labs LLC. Security Operations Architect

This rule finds hosts where a **known-compromised or malicious AI-ecosystem package or extension** was installed or is present. Examples are a backdoored npm package aimed at Cursor users, a fake DeepSeek or Claude SDK on PyPI, the trojanised Amazon Q VS Code extension, the Nx "s1ngularity" releases that turned local AI CLIs against their owners, and AI-branded Chrome extensions hijacked through the Chrome Web Store. Every hit is an indicator match from a maintained IOC macro, not a keyword guess. The rule creates risk on the host (`dest`, system) and, when the account is a real person, on the `user`. It creates no notable.

v1.0 matched any AI keyword (`copilot`, `openai`, `cursor`, `continue`...) in any `npm`/`pip`/`code` command. That made every routine `pip install openai` look like a "compromised plugin". Its browser branch also required `POST`/`PUT` to the store web pages, but installs and update checks are `GET` requests to the update and download endpoints. v1.1 replaces both with an IOC match.

### Prerequisites
Either data path is enough. The two branches are joined with `append`, each one keeps only its own IOC rows, and a missing data model only empties its own branch.

| Data | Fields used | What it adds | If absent |
|---|---|---|---|
| `Endpoint.Processes` (accelerated) | `process` (full command line), `process_name`, `parent_process_name`, `user`, `dest` | Package names and versions in installer and runner command lines: `npm install/add/exec`, `npx` (including `npx.cmd` and `node ... npx-cli.js`), `yarn add/dlx`, `pnpm add/install/dlx`, `bun add`, `bunx`, `pip`/`pipx install/run`, `uv add/pip/tool`, `uvx` and `code`/`cursor --install-extension` | Package and IDE-extension IOCs are only visible through the Web branch |
| `Web` (accelerated) with **full URL paths** | `url`, `user`, `src` | Chrome and Edge extension fetches (`clients2.google.com/service/update2/crx?...x=id=<extension id>`), CRX downloads (including the Web Store redirect host `*.gvt1.com/edgedl/chromewebstore/`), VSIX downloads, npm tarball URLs from `registry.npmjs.org` and `registry.yarnpkg.com` (including scoped `@scope/name/-/name-<ver>.tgz`) and PyPI files | Browser-extension IOCs cannot be seen. A proxy or SSE that logs only domains (no TLS inspection) never matches |

- The process command line must be populated. EDR feeds that map only `process_name` cannot match package names.
- No ES lookups are used. No `hdsi_ai_rba_common` macro is used either. The common package stays a prerequisite so the suite's risk aggregators and health checks deploy with it.
- DNS cannot carry package names or extension IDs, so it is not used. `<publisher>.gallery.vsassets.io` lookups show only the VS Code publisher.

### How it works
- **Web branch (main search):** `tstats` over `Web`, pre-filtered inline by `..._store_urls` (extension fetch/download endpoints and registry tarball paths) and `..._web_filter`. It splits by `user`, `src` and `url`, and `src` becomes `dest`. This is the high-volume branch (tens of thousands of URL rows per 4 h on a large Chrome fleet with TLS inspection), so it runs as the main search, where subsearch limits do not apply.
- **Process branch (`append` subsearch):** `tstats` over `Endpoint.Processes`, pre-filtered inline by `..._install_commands` (installer and runner command shapes) and `..._filter`. It splits by `user`, `dest`, `process_name` and `process`.
- **IOC tagging inside each branch (`..._ioc_tag`):** the evidence (command line or URL) is lower-cased, `_` is folded to `-` (PyPI treats them as the same character), and `..._ioc_match(ioc_text)` returns an IOC label or null. Only labelled rows leave a branch. This keeps the appended subsearch tiny, so Splunk's subsearch limits (50,000 rows, 60 s) can never drop evidence before it is checked.
- **ATT&CK mapping per row:** packages map to `T1195.001`, IDE extensions to `T1176.002` and browser extensions to `T1176.001`.
- **Risk objects:** non-person accounts never become a user risk object. The search nulls `NT AUTHORITY\*` and machine accounts (`HOST$`, also in UPN form `HOST$@DOMAIN`), plus any name in `..._service_accounts` (Windows built-ins including `LocalSystem`, the Codex sandbox accounts `CodexSandboxOffline`/`CodexSandboxOnline`, the firewall placeholder `Web browser`, `root`, `jenkins`, `gitlab-runner`, `runner`, `svc_*` and other CI identities). The name is matched with any `DOMAIN\` prefix or `@domain` suffix removed. Build agents therefore raise risk on the host only. Rows with neither object are dropped.
- **Display and drilldown fields:** `title_object` (the host, or the user when there is no host) names the finding in `rule_title`; `dest_display` replaces an empty host in the messages. `dest_drill` and `user_drill` are drilldown-safe copies (a backslash or quote becomes `*`, since `DOMAIN\user` loses its backslash in a quoted SPL term) and are `__none__` when the object is absent, so an empty token never matches everything.
- **Aggregation:** one row per `user` + `dest` (null-safe), with `ioc_list`, `install_vector`, `install_tool`, `parent_process_name` and `evidence_sample`.
- **Scoring is static:** `dest` 60 and `user` 40. A hit is a confirmed indicator, so no multiplier is applied, and the RBA aggregators decide escalation. Suppression is 24 h per `dest`,`user`, because a browser re-fetches an extension it cannot install or keep (for example a policy force-install) many times a day.
- Cadence: every 15 minutes (`-20m@m` to `-5m@m`).

### Tuning macros
| Macro | Ships as | Purpose |
|---|---|---|
| `hdsi_ai_compromised_plugin_extension_installation_filter` | `()` | Exclusions inside the process `tstats` where clause (`Processes.*` names), e.g. a malware-analysis sandbox |
| `hdsi_ai_compromised_plugin_extension_installation_web_filter` | `()` | Exclusions inside the Web `tstats` where clause (`Web.*` names) |
| `hdsi_ai_compromised_plugin_extension_installation_install_commands` | npm install/add/exec, npx, `npx.cmd`, `npx-cli`, yarn add/dlx, pnpm add/install/dlx, bun add, bunx, pip/pipx install/run, uv add/pip/tool, uvx, `--install-extension` | Process pre-filter. Add your installers here (e.g. `poetry add`, `conda install`) |
| `hdsi_ai_compromised_plugin_extension_installation_service_accounts` | Quoted regex: Windows built-ins (incl. `localsystem`), `codexsandbox(offline\|online)`, `web browser`, `root`, `daemon`, `nobody`, `jenkins`, `gitlab-runner`, `runner`, `github-runner`, `actions-runner`, `buildkite-agent`, `teamcity`, `bamboo`, `azure-pipelines`, `azdevops`, `vsts*`, `svc[-_.]*` | Non-person accounts that never become a user risk object. Add your build and service-account naming |
| `hdsi_ai_compromised_plugin_extension_installation_store_urls` | Chrome/Edge update + CRX (incl. `*.gvt1.com/edgedl/chromewebstore/`), VS Code Marketplace/vsassets, Open VSX, npm (`registry.npmjs.org`, `registry.yarnpkg.com`) and PyPI tarballs | Web pre-filter. Add internal mirrors (Artifactory, Nexus, Verdaccio) and other public registries your developers use here; a URL the pre-filter drops is never IOC-checked |
| `hdsi_ai_compromised_plugin_extension_installation_ioc_match(1)` | Public-advisory IOC list (below) | `case(match(...), "label", ...)` IOC list. Add a `match($text$, "<regex>"), "<Ecosystem>: <name> (<yyyy-mm>)"` pair per advisory. Labels starting `Browser` or `VS Code` drive the ATT&CK mapping |
| `hdsi_ai_compromised_plugin_extension_installation_ioc_tag` | `eval ioc_text ... \| eval ioc_name ... \| where isnotnull(ioc_name)` | Internal: the per-branch IOC filter. Do not move it after the `append`; that brings back the subsearch row limit |
| `hdsi_ai_compromised_plugin_extension_installation_customizations` | `search *` | Post-normalisation hook (fields: `user`, `dest`, `ioc_name`, `ioc_list`, `install_vector`, `install_tool`, `parent_process_name`, `evidence`) |
| `hdsi_ai_compromised_plugin_extension_installation_risk_score` | `search *` | Last pipe. Set a numeric `risk_score` (≤100) here to override both static scores |

Shipped IOC list (public advisories, checked 2026-10):

| Ecosystem | Indicator | Advisory |
|---|---|---|
| npm | `nx` 20.9.0, 20.10.0–20.12.0, 21.5.0–21.8.0; `@nx/devkit`, `@nx/js`, `@nx/workspace`, `@nx/node` 20.9.0/21.5.0; `@nx/eslint` 21.5.0; `@nx/key`, `@nx/enterprise-cloud` 3.2.0. Install specs (`@nx/devkit@21.5.0`) and registry tarball paths (`@nx/devkit/-/devkit-21.5.0.tgz`, also `%2f`-encoded) both match. Prereleases of the same number (`nx@21.5.0-beta.1`) do not | Nx "s1ngularity", GHSA-cxm3-wv7p-598c / CVE-2025-10894 (2025-08). Its postinstall ran Claude, Gemini and Amazon Q CLIs for recon |
| npm | `sw-cur`, `sw-cur1`, `aiide-cur` | Backdoor targeting Cursor AI IDE installs (2025-05) |
| npm | `postmark-mcp` (unscoped) | Malicious MCP server that BCC'd mail (2025-09). The scoped `@<org>/postmark-mcp` is not matched |
| PyPI | `gptplus`, `claudeai-eng` | Fake ChatGPT/Claude SDKs dropping JarkaStealer (2024-11) |
| PyPI | `deepseeek`, `deepseekai` | Fake DeepSeek SDK infostealer (2025-01) |
| PyPI | `aliyun-ai-labs-snippets-sdk`, `ai-labs-snippets-sdk`, `aliyun-ai-labs-sdk` | Malicious "AI Labs" SDKs (2025-05) |
| PyPI | `ultralytics` 8.3.41, 8.3.42, 8.3.45, 8.3.46 (spec, wheel or sdist; not `rc`/`.dev`/`.post` builds) | Compromised YOLO releases with a cryptominer (2024-12) |
| PyPI | `torchtriton` | PyTorch nightly dependency confusion (2022-12) |
| VS Code | `amazonwebservices.amazon-q-vscode` 1.84.0 | Wiper prompt injected into Amazon Q (2025-07) |
| Chrome | `bibjgkidgpfbblifamdlkdlhgihmfohh`, `pkgciiiancapdlpcbppfkmeaieppikkk`, `cedgndijpacnfbdggppddacngjfdkaca`, `bbdnohkpnbkdkmnkddobeafboooinpla`, `epdjhgbipjpbbhoccdeipghoihibnfja` | AI-branded extensions hijacked in the 2024 Chrome Web Store OAuth-phishing campaign |

Test a candidate regex before adding it. Run `| makeresults | eval ioc_text=" npm install <name>@<ver> " | eval ioc_name=`hdsi_ai_compromised_plugin_extension_installation_ioc_match(ioc_text)``. In the regex, use `[.]` for a dot, `\x22` for a double quote and `\x5c` for a backslash.

### Threshold
None. A single IOC match is the signal. Volume is controlled by the IOC list and the 24 h suppression, not by a count.

### Known false positives / Limitations
- **Lockfile and transitive installs are invisible on the command line.** `npm install`, `npm ci` and `pip install -r requirements.txt` without a package argument made up most install commands in validation, and they name no package. Compromised transitive dependencies (the usual s1ngularity path, including the scoped `@nx/*` plugins) are caught by the Web branch when the proxy logs full registry tarball URLs, or by an SCA/EDR file inventory, which is out of scope here. This is the rule's best coverage path where it exists: Tenant A's Web model logs about 950 distinct versioned npm tarball URLs per 24 h (`<name>/-/<name>-X.Y.Z.tgz`, 262 of them scoped `@scope/<name>/-/...`), every one of which the Web branch IOC-checks (0 IOC). Tenants B–D log no registry paths, so there transitive installs are visible only through an EDR or SCA inventory.
- **Version-pinned IOCs need a version in the evidence.** `npm i nx` (no version) does not match. A tarball URL (`nx/-/nx-21.5.0.tgz`) or a pinned spec (`nx@21.5.0`) does.
- **Chrome IDs mostly show install fetches, not steady-state presence.** In Tenant A data, 98% of the `update2/crx` GET requests carry `v=0.0.0.0`: an on-demand install, or a policy force-install fetch that the browser repeats. Routine update checks for already-installed extensions largely go to the POST JSON update endpoint, which carries no extension ID in the URL. So an old hijacked extension that is already installed may never appear. Expect to see `v=0.0.0.0` in `evidence_sample`. Treat a hit as "the browser tried to install or fetch this ID", then confirm on the endpoint (browser extension inventory or EDR). Several hijacked extensions were later republished clean under the same ID, so check the installed version before escalating.
- **Prereleases are not IOC hits.** Pinned versions reject `-beta`/`-rc`/`-canary` (npm) and `rc`/`.dev`/`.post` (PyPI) builds of the same number. If an advisory names a prerelease, add it as its own `match()` pair.
- **Download hosts outside the pre-filter are not inspected.** The shipped list covers the public npm (`registry.npmjs.org`, `registry.yarnpkg.com`), PyPI, VS Code/Open VSX and Chrome/Edge store endpoints. Internal mirrors and other registries need their URL pattern in `..._store_urls`.
- **Domain-only web logs** (an SSE that logs app names, or no TLS inspection) carry no extension IDs or package paths, so the Web branch returns nothing there.
- **Drilldowns are per vector.** For process-branch rows `dest` is the hostname; for web-branch rows `dest` is the source IP (`src`) the proxy logged. The process drilldown searches `Processes.dest` or `Processes.user`, the web drilldown `Web.src` or `Web.user`, so each still returns the user's own activity when the other object is absent, but the process drilldown finds no host for a web row (an IP) and vice versa. Use the drilldown that matches `install_vector`; ES asset correlation maps the IP to a host in the risk event.
- **Runner coverage is by command-line token.** `npx`, `bunx`, `uvx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `pipx run`, `uv tool run`, `npx.cmd` and `npx-cli` are covered. A runner launched under another name (an IDE that spawns `node` with a bundled script) is invisible until you add its pattern to `..._install_commands`. `npx.cmd` also matches some unrelated compiler temp files; the IOC check drops them.
- **The process branch is a subsearch.** It is light (under 10 s per 4 h in validation), but on an extremely large `Endpoint.Processes` model it could still hit the 60 s subsearch time limit. Check the job inspector for `[subsearch]` warnings after enablement.
- **Security research and sandbox hosts** that deliberately install malware samples will match. Exclude them with `..._filter` / `..._web_filter`.
- The IOC list is a seed list from public advisories. It goes stale unless maintained. Review it whenever an AI-ecosystem supply-chain advisory is published.

### Validation
Read-only tests on 4 production ES tenants, 2026-10-09 (UTC).

| Tenant | Process command lines with installer args | Full-path extension/registry URLs in Web | Parses (search + 3 drilldowns) | Rows: 15 min / 4 h / 24 h | Runtime: 15 min / 4 h / 24 h | Notes |
|---|---|---|---|---|---|---|
| A | Yes: 54 install commands over 7 d on 5 hosts, all real users | Yes: about 5,000 distinct user/source/URL rows per 15 min and about 61,500 per 4 h; user filled on 89%. Includes about 950 distinct versioned npm tarball URLs per 24 h (262 scoped) and 21 Web Store CRX URLs on `*.gvt1.com/edgedl/chromewebstore/` per 4 h; no `registry.yarnpkg.com` | OK | 0 / 0 / 0 | 15 s / 31 s / 130 s | No IOC in 7 d of commands or 24 h of URLs (the 24 h npm tarball scan included). Transitive npm installs are visible here through tarball URLs. 4 h and 24 h runs completed with no subsearch truncation or auto-finalize message |
| B | No: Endpoint data has almost no command lines | No: the Web model is inbound load-balancer/WAF traffic | OK | 0 / 0 / 0 | 6 s / 39 s / 196 s | No data path. The Web branch scans the large inbound Web model for nothing, so exclude it with `..._web_filter` or leave the rule disabled |
| C | Yes: 142 install commands over 7 d on 4 hosts, 97% run as SYSTEM or machine accounts (CI build agents) | No: the SSE logs domains only | OK | 0 / 0 / 0 | 4 s / 5 s / 7 s | Build-agent installs would score the host only. Most commands are lockfile installs (`npm install` / `pnpm install` with no package name) |
| D | No | No: the Web model is inbound IIS traffic | OK | 0 / 0 / 0 | 3 s / 3 s / 3 s | No data path |

Other checks:
- **Subsearch limits (fixed in this version):** an earlier v1.1 draft ran the IOC match after the `append`, with the Web branch as the subsearch. On Tenant A its 4 h run was truncated (56,808 rows cut to 50,000) and its 24 h run was truncated and auto-finalized at 60 s. Those runs reported 0 rows but did not prove it. A separate direct (non-subsearch) 24 h IOC scan of 12,209 distinct URLs found 0 IOC. The shipped search tags IOCs inside each branch and runs the Web branch as the main search, and the A runs above completed with no truncation.
- **IOC regex inside Splunk:** a `makeresults` control of 49 positive and negative strings passed 49/49 on two tenants. The strings covered command lines, Windows paths, npm/PyPI tarball URLs, and Chrome/Edge update URLs, including URL-encoded `id%3D`. The scoped `@nx/*` tarball forms (`@nx/devkit/-/devkit-21.5.0.tgz`, `@nx%2fjs/-/js-20.9.0.tgz`) were added and checked, along with near-miss versions that must not match.
- **Pipeline:** an end-to-end run on 17 synthetic rows (8 URLs, 9 command lines) emitted exactly the 13 IOC rows as 11 user/host rows and dropped the 4 benign ones (`pip install openai`, a clean extension ID, `@nx/devkit` 21.4.0, `@nx/js` 20.9.1). It nulled `jenkins`, `root`, `CORP\gitlab-runner`, `svc_build@<domain>`, `HOST$`, `NT AUTHORITY\SYSTEM` and `unknown` while keeping the host, and kept real users. `bunx`, `pnpm dlx`, `npm exec`, `npx.cmd` and `npx-cli.js` invocations matched.
- **Edge cases (second review round):** a `makeresults` control of 19 strings passed 19/19 on Tenants A and C. It covered `nx@21.5.0-beta.1`, `@nx/devkit/-/devkit-21.5.0-rc.1.tgz`, a canary tarball and `ultralytics==8.3.41rc1`/`.dev0` (no match), `registry.yarnpkg.com` tarballs for `nx`, `sw-cur` and `postmark-mcp`, ultralytics wheel and sdist names, and a `*.gvt1.com/edgedl/chromewebstore/` CRX URL (match). An identity control of 14 names passed 14/14: `WS01$@CORP.LOCAL`, `LocalSystem`, `CodexSandboxOffline`/`Online`, `Web browser`, `SYSTEM`, `NT AUTHORITY\SYSTEM`, `CORP\gitlab-runner`, `svc_build@<domain>`, `HOST$` and `unknown` were nulled; `DOMAIN\user`, `user@domain` and bare user names were kept, with `user_drill` replacing the backslash.
- **Re-run after these changes (4 h, auto window):** 0 rows on all tenants, no errors, in 34 s (A), 32 s (B), 4 s (C) and 3 s (D). The search and all three drilldowns parse on A–D.
- **v1.0 comparison:** the v1.0 AI-keyword logic matched nothing in 3 d on any tenant either. Its browser branch could never match, because it required `POST` to store pages, while A's real extension fetches are `GET`.

### Deployment
The package ships with `enable_alerting: false`. Before enablement, confirm that at least one data path exists on the target tenant: process command lines that contain installer arguments, or full-path proxy URLs for the extension update endpoint. Confirm the rendered search parses and completes on a 15-minute window. Load any tenant-specific IOCs and mirror URLs into the macros. The rule is risk-only (no notable). Enabling it is a separately approved change.
