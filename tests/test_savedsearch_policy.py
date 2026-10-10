"""Saved-search release conventions: hook macros, notable/risk policy, risk and drilldown JSON."""

from __future__ import annotations

import json
import re

import pytest

from .conftest import (
    drilldowns,
    package_macro_stanzas,
    packages_with_role,
    risk_enabled,
    role,
    savedsearches,
    search_packages,
)

MITRE_ID_RE = re.compile(r"^(TA\d{4}|T\d{4}(\.\d{3})?)$")
UNDERSCORE_TOKEN_RE = re.compile(r"\$_[A-Za-z0-9_.]*\$")
DRILLDOWN_KEYS = {"name", "search", "earliest_offset", "latest_offset"}
FROM_DATAMODEL_WHERE_RE = re.compile(r"(?:^|\|)\s*from\s+datamodel\s*:\s*(?:\"[^\"]*\"|\S+)\s+where\b", re.IGNORECASE)
BY_CLAUSE_RE = re.compile(r"\bby\s+([^|\]]+)", re.IGNORECASE)
_CRON_FIELD = r"(\*(?:/\d+)?|[\d,\-/]+)"
CRON_RE = re.compile(rf"^{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}$")


def _stanzas(package: str) -> dict[str, dict[str, str]]:
    return {k: v for k, v in savedsearches(package).items() if "search" in v}


def _has_macro(package: str, name: str) -> bool:
    return any(re.sub(r"\(\d+\)$", "", s) == name for s in package_macro_stanzas(package))


# ---------------------------------------------------------------------------
# Hook macros: _filter (inline, never piped), _customizations (piped), _risk_score (last pipe)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("package", search_packages())
def test_filter_macro_inline_not_piped(package):
    macro = f"{package}_filter"
    assert _has_macro(package, macro), f"{package}: macros.conf has no [{macro}] stanza"
    errors = []
    for stanza, kv in _stanzas(package).items():
        spl = kv["search"]
        if f"`{macro}" not in spl:
            errors.append(f"[{stanza}] never references `{macro}`")
        if re.search(rf"\|\s*`{re.escape(macro)}(\([^`]*\))?`", spl):
            errors.append(f"[{stanza}] pipes `{macro}`; it must sit inside the base search / tstats where clause")
    assert not errors, f"{package}: " + "; ".join(errors)


@pytest.mark.parametrize("package", search_packages())
def test_customizations_macro_piped(package):
    macro = f"{package}_customizations"
    assert _has_macro(package, macro), f"{package}: macros.conf has no [{macro}] stanza"
    errors = [
        f"[{stanza}] does not pipe `{macro}`"
        for stanza, kv in _stanzas(package).items()
        if not re.search(rf"\|\s*`{re.escape(macro)}`", kv["search"])
    ]
    assert not errors, f"{package}: " + "; ".join(errors)


@pytest.mark.parametrize("package", search_packages())
def test_risk_score_macro_is_last_pipe(package):
    macro = f"{package}_risk_score"
    risky = {s: kv for s, kv in _stanzas(package).items() if risk_enabled(kv)}
    if not risky:
        pytest.skip("action.risk = 0")
    assert _has_macro(package, macro), f"{package}: action.risk = 1 but macros.conf has no [{macro}] stanza"
    errors = [
        f"[{stanza}] last pipe is {kv['search'].rstrip().rsplit('|', 1)[-1].strip()!r}, expected `{macro}`"
        for stanza, kv in risky.items()
        if not re.search(rf"\|\s*`{re.escape(macro)}`\s*$", kv["search"])
    ]
    assert not errors, f"{package}: " + "; ".join(errors)


# ---------------------------------------------------------------------------
# Notable / risk policy by package role
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("package", search_packages())
def test_notable_risk_policy(package):
    pkg_role = role(package)
    if pkg_role in {"health", "hunting"}:
        pytest.skip(f"{pkg_role} package is exempt from the notable/risk policy")
    expected = {"detection": ("0", "1"), "aggregator": ("1", "0")}[pkg_role]
    errors = []
    for stanza, kv in _stanzas(package).items():
        actual = (kv.get("action.notable", "").strip(), kv.get("action.risk", "").strip())
        if actual != expected:
            errors.append(
                f"[{stanza}] action.notable={actual[0]!r} action.risk={actual[1]!r}, "
                f"{pkg_role} requires notable={expected[0]} risk={expected[1]}"
            )
    assert not errors, f"{package}: " + "; ".join(errors)


@pytest.mark.parametrize("package", search_packages())
def test_required_scheduling_fields(package):
    required = ("description", "cron_schedule", "dispatch.earliest_time", "dispatch.latest_time")
    errors = []
    for stanza, kv in _stanzas(package).items():
        missing = [k for k in required if not kv.get(k, "").strip()]
        if missing:
            errors.append(f"[{stanza}] missing {missing}")
        cron = kv.get("cron_schedule", "").strip()
        if cron and not CRON_RE.match(cron):
            errors.append(f"[{stanza}] invalid cron_schedule {cron!r}")
        if len(kv.get("description", "")) < 20:
            errors.append(f"[{stanza}] description is trivially short")
    assert not errors, f"{package}: " + "; ".join(errors)


# ---------------------------------------------------------------------------
# Risk action
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("package", search_packages())
def test_risk_action_params(package):
    risky = {s: kv for s, kv in _stanzas(package).items() if risk_enabled(kv)}
    if not risky:
        pytest.skip("action.risk = 0")
    errors = []
    for stanza, kv in risky.items():
        if not kv.get("action.risk.param._risk_message", "").strip():
            errors.append(f"[{stanza}] action.risk.param._risk_message is missing")
        raw = kv.get("action.risk.param._risk", "")
        try:
            entries = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"[{stanza}] action.risk.param._risk is not valid JSON ({exc})")
            continue
        if not isinstance(entries, list) or not entries:
            errors.append(f"[{stanza}] action.risk.param._risk must be a non-empty JSON list")
            continue
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                errors.append(f"[{stanza}] risk entry {i} is not an object")
                continue
            score = entry.get("risk_score")
            if isinstance(score, bool) or not isinstance(score, int):
                errors.append(f"[{stanza}] risk entry {i} risk_score={score!r} must be a JSON integer, not a token")
            elif not 1 <= score <= 100:
                errors.append(f"[{stanza}] risk entry {i} risk_score={score} outside 1..100")
            if entry.get("risk_object_type") not in {"user", "system"}:
                errors.append(f"[{stanza}] risk entry {i} risk_object_type={entry.get('risk_object_type')!r}")
            if not entry.get("risk_object_field"):
                errors.append(f"[{stanza}] risk entry {i} has no risk_object_field")
    assert not errors, f"{package}: " + "; ".join(errors)


@pytest.mark.parametrize("package", search_packages())
def test_detection_id_matches_package(package):
    errors = []
    for stanza, kv in _stanzas(package).items():
        # wildcard values are filters on contributing risk events (aggregators), not assignments
        ids = {i for i in re.findall(r'detection_id\s*=\s*"([^"]+)"', kv["search"]) if "*" not in i}
        if risk_enabled(kv) and not ids:
            errors.append(f"[{stanza}] action.risk = 1 but the search never sets detection_id")
        wrong = sorted(ids - {package})
        if wrong:
            errors.append(f"[{stanza}] sets detection_id {wrong}, expected {package!r}")
    assert not errors, f"{package}: " + "; ".join(errors)


@pytest.mark.parametrize("package", search_packages())
def test_no_underscore_tokens_in_analyst_text(package):
    fields = (
        "action.risk.param._risk_message",
        "action.notable.param.rule_title",
        "action.notable.param.rule_description",
        "action.notable.param.drilldown_searches",
    )
    errors = []
    for stanza, kv in _stanzas(package).items():
        for field in fields:
            tokens = sorted(set(UNDERSCORE_TOKEN_RE.findall(kv.get(field, ""))))
            if tokens:
                errors.append(f"[{stanza}] {field} uses internal token(s) {tokens}")
    assert not errors, f"{package}: " + "; ".join(errors)


# ---------------------------------------------------------------------------
# Drilldowns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("package", search_packages())
def test_drilldown_schema(package):
    errors = []
    for stanza, kv in _stanzas(package).items():
        try:
            items = drilldowns(kv)
        except (ValueError, json.JSONDecodeError) as exc:
            errors.append(f"[{stanza}] drilldown_searches is not a JSON list ({exc})")
            continue
        for i, dd in enumerate(items):
            if not isinstance(dd, dict):
                errors.append(f"[{stanza}] drilldown {i} is not an object")
                continue
            if set(dd) != DRILLDOWN_KEYS:
                errors.append(f"[{stanza}] drilldown {i} keys {sorted(dd)}, expected {sorted(DRILLDOWN_KEYS)}")
            search = str(dd.get("search", ""))
            if not search.strip():
                errors.append(f"[{stanza}] drilldown {i} has an empty search")
            if FROM_DATAMODEL_WHERE_RE.search(search):
                errors.append(f"[{stanza}] drilldown {dd.get('name', i)!r} uses '| from datamodel:... where'")
    assert not errors, f"{package}: " + "; ".join(errors)


def _url_domain_without_site(spl: str) -> list[str]:
    bad = []
    for clause in BY_CLAUSE_RE.findall(spl):
        fields = set(re.split(r"[\s,]+", clause.strip()))
        if "Web.url_domain" in fields and "Web.site" not in fields:
            bad.append(clause.strip()[:80])
    return bad


@pytest.mark.parametrize("package", search_packages())
def test_web_drilldowns_group_by_site(package):
    errors = []
    for stanza, kv in _stanzas(package).items():
        try:
            items = drilldowns(kv)
        except (ValueError, json.JSONDecodeError):
            continue  # reported by test_drilldown_schema
        for dd in items:
            if isinstance(dd, dict):
                for clause in _url_domain_without_site(str(dd.get("search", ""))):
                    errors.append(f"[{stanza}] drilldown {dd.get('name')!r} groups 'by {clause}' without Web.site")
    assert not errors, f"{package}: " + "; ".join(errors)


@pytest.mark.parametrize("package", search_packages())
def test_web_search_groups_by_site(package):
    """Proxies often populate Web.site but not Web.url_domain; grouping must carry both."""
    errors = [
        f"[{stanza}] groups 'by {clause}' without Web.site"
        for stanza, kv in _stanzas(package).items()
        for clause in _url_domain_without_site(kv["search"])
    ]
    assert not errors, f"{package}: " + "; ".join(errors)


# ---------------------------------------------------------------------------
# Annotations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("package", search_packages())
def test_annotations(package):
    errors = []
    for stanza, kv in _stanzas(package).items():
        raw = kv.get("action.correlationsearch.annotations", "")
        try:
            ann = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"[{stanza}] annotations not valid JSON ({exc})")
            continue
        if not isinstance(ann, dict):
            errors.append(f"[{stanza}] annotations must be a JSON object")
            continue
        mitre = ann.get("mitre_attack")
        if mitre is None:
            if role(package) in {"detection", "aggregator", "hunting"}:
                errors.append(f"[{stanza}] annotations has no mitre_attack list")
            continue
        if not isinstance(mitre, list) or not mitre:
            errors.append(f"[{stanza}] annotations.mitre_attack must be a non-empty list")
            continue
        bad = [m for m in mitre if not isinstance(m, str) or not MITRE_ID_RE.match(m)]
        if bad:
            errors.append(f"[{stanza}] invalid MITRE ID(s) {bad}")
    assert not errors, f"{package}: " + "; ".join(errors)


# ---------------------------------------------------------------------------
# Health checks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("package", packages_with_role("health"))
def test_health_email_uses_config_token(package):
    errors = []
    for stanza, kv in _stanzas(package).items():
        if kv.get("action.email.to") is None:
            continue
        if "alert_email_to" not in kv["search"]:
            errors.append(f"[{stanza}] does not load alert_email_to from ai_detection_config")
        if kv["action.email.to"].strip() != "$result.alert_email_to$":
            errors.append(f"[{stanza}] action.email.to must be $result.alert_email_to$")
    assert not errors, f"{package}: " + "; ".join(errors)
