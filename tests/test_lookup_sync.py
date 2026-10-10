"""Hardcoded tstats IN() lists stay in sync with the lookup CSVs; key detections stay lookup-driven.

The highest-risk maintenance failure is a hardcoded process/domain list in a tstats
prefilter drifting away from the authoritative lookup: every value in such a list
must exist (enabled) in the matching CSV.
"""

from __future__ import annotations

import fnmatch
import re

import pytest

from .conftest import search_of


def _in_values(spl: str, field: str) -> set[str]:
    values: set[str] = set()
    for m in re.finditer(rf"{re.escape(field)}\s+IN\s*\(([^)]+)\)", spl, re.IGNORECASE):
        values.update(v.lower() for v in re.findall(r'"([^"]*)"', m.group(1)))
    return values


def _enabled(rows, column, **match):
    return {
        r[column].lower()
        for r in rows
        if r.get("enabled") == "1" and all(r.get(k) in v for k, v in match.items())
    }


PROCESS_SYNC = [
    ("hdsi_ai_unsanctioned_cli_execution", "Processes.process_name", ("cli",)),
    ("hdsi_ai_scripted_cli_invocation", "Processes.process_name", ("cli",)),
    ("hdsi_ai_unsanctioned_desktop_app_execution", "Processes.process_name", ("desktop_app",)),
    ("hdsi_ai_local_llm_framework_execution", "Processes.process_name", ("local_llm",)),
]


@pytest.mark.parametrize(("package", "field", "usage_types"), PROCESS_SYNC, ids=[p[0] for p in PROCESS_SYNC])
def test_process_prefilter_in_lookup(package, field, usage_types, tool_processes):
    spl = search_of(package)
    assert spl, f"{package}: saved search not found"
    listed = _in_values(spl, field)
    if not listed:
        pytest.skip(f"{package} has no hardcoded {field} IN() list")
    known = _enabled(tool_processes, "process_name_lc", usage_type=usage_types)
    # a wildcard entry (e.g. "koboldcpp*") is in sync when it covers at least one enabled lookup row
    drift = sorted(v for v in listed - known if not ("*" in v and any(fnmatch.fnmatch(k, v) for k in known)))
    assert not drift, (
        f"{package}: {field} IN() values not in ai_tool_processes.csv (usage_type in {usage_types}, enabled=1): {drift}"
    )


DOMAIN_SYNC = [
    ("hdsi_ai_dns_queries_to_ai_domains", "DNS.query", None),
    ("hdsi_ai_api_access_from_non_dev_endpoint", "Web.url_domain", ("api",)),
]


@pytest.mark.parametrize(("package", "field", "usage_types"), DOMAIN_SYNC, ids=[p[0] for p in DOMAIN_SYNC])
def test_domain_prefilter_in_lookup(package, field, usage_types, provider_domains):
    spl = search_of(package)
    assert spl, f"{package}: saved search not found"
    listed = _in_values(spl, field)
    if not listed:
        pytest.skip(f"{package} has no hardcoded {field} IN() list")
    match = {"usage_type": usage_types} if usage_types else {}
    drift = sorted(listed - _enabled(provider_domains, "domain", **match))
    assert not drift, f"{package}: {field} IN() values not in ai_provider_domains.csv: {drift}"


def test_agent_framework_lists_in_sync():
    """Autonomous-action parent list must cover every agent framework process."""
    procs = _in_values(search_of("hdsi_ai_agent_framework_execution"), "Processes.process_name")
    parents = _in_values(search_of("hdsi_ai_agent_autonomous_action_detection"), "Processes.parent_process_name")
    if not procs or not parents:
        pytest.skip("one of the agent framework searches has no hardcoded IN() list")
    missing = sorted(procs - parents)
    assert not missing, (
        "hdsi_ai_agent_framework_execution process names missing from "
        f"hdsi_ai_agent_autonomous_action_detection parent list: {missing}"
    )


LOOKUP_DRIVEN = [
    ("hdsi_ai_prompt_injection_indicators_in_web_uploads",
     ("inputlookup ai_prompt_injection_patterns", "`ai_prompt_injection_patterns_enabled`")),
    ("hdsi_ai_api_key_exposure_in_code_dlp",
     ("inputlookup ai_api_key_patterns", "`ai_api_key_patterns_enabled`")),
]


@pytest.mark.parametrize(("package", "markers"), LOOKUP_DRIVEN, ids=[p[0] for p in LOOKUP_DRIVEN])
def test_pattern_detections_use_lookup(package, markers):
    spl = search_of(package)
    assert spl, f"{package}: saved search not found"
    assert any(m in spl for m in markers), f"{package}: must take its patterns from the lookup ({markers})"


def test_deepfake_detection_avoids_unbounded_wildcard():
    spl = search_of("hdsi_ai_deepfake_tool_execution_access")
    assert spl, "hdsi_ai_deepfake_tool_execution_access saved search not found"
    assert "Processes.process_name=*" not in spl, (
        "deepfake detection must not scan Endpoint.Processes with an unbounded process_name=* wildcard"
    )
