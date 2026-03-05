"""Validate SPL syntax in savedsearches.conf."""

from __future__ import annotations

import json
import re

from .conftest import extract_lookup_refs, extract_macro_refs

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_balanced(text: str, open_ch: str, close_ch: str) -> tuple[bool, str]:
    """Check that open/close characters are balanced, ignoring quoted strings."""
    depth = 0
    in_dq = False
    in_sq = False
    for i, ch in enumerate(text):
        if ch == '"' and not in_sq:
            in_dq = not in_dq
            continue
        if ch == "'" and not in_dq:
            in_sq = not in_sq
            continue
        if in_dq or in_sq:
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth < 0:
                return False, f"Extra '{close_ch}' at position {i}"
    if depth != 0:
        return False, f"Unmatched '{open_ch}' ({depth} unclosed)"
    return True, ""


def _check_quotes_balanced(text: str, quote_ch: str) -> tuple[bool, str]:
    """Check that a quote character appears an even number of times.

    This is a simplified heuristic; Splunk SPL allows embedded quotes in some
    contexts, but mismatched quotes almost always indicate an error.
    """
    # Strip escaped quotes first
    stripped = text.replace(f"\\{quote_ch}", "")
    count = stripped.count(quote_ch)
    if count % 2 != 0:
        return False, f"Odd number of {quote_ch} characters ({count})"
    return True, ""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBalancedDelimiters:
    """Every search string must have balanced parentheses, brackets, and quotes."""

    def test_parentheses(self, savedsearches):
        for name, props in savedsearches.items():
            if name == "default":
                continue
            search = props.get("search", "")
            if not search:
                continue
            ok, msg = _check_balanced(search, "(", ")")
            assert ok, f"[{name}] Unbalanced parentheses: {msg}"

    def test_square_brackets(self, savedsearches):
        for name, props in savedsearches.items():
            if name == "default":
                continue
            search = props.get("search", "")
            if not search:
                continue
            # Skip risk JSON fields — they use [ ] for JSON arrays
            # We strip out JSON-like [...] content before checking
            cleaned = re.sub(r'\[{.*?}\]', '', search)
            ok, msg = _check_balanced(cleaned, "[", "]")
            assert ok, f"[{name}] Unbalanced square brackets: {msg}"

    def test_double_quotes(self, savedsearches):
        for name, props in savedsearches.items():
            if name == "default":
                continue
            search = props.get("search", "")
            if not search:
                continue
            ok, msg = _check_quotes_balanced(search, '"')
            assert ok, f"[{name}] Unbalanced double quotes: {msg}"


class TestMacroReferences:
    """Every macro referenced in SPL must exist in macros.conf."""

    def test_all_macros_defined(self, savedsearches, macros):
        macro_stanzas = set(macros.keys()) - {"default"}
        errors = []
        for name, props in savedsearches.items():
            if name == "default":
                continue
            search = props.get("search", "")
            if not search:
                continue
            refs = extract_macro_refs(search)
            for ref in refs:
                if ref not in macro_stanzas:
                    errors.append(f"[{name}] references undefined macro `{ref}`")
        assert not errors, "Undefined macro references:\n" + "\n".join(errors)


class TestLookupReferences:
    """Every ``| lookup`` in SPL must reference a transform in transforms.conf."""

    def test_all_lookups_defined(self, savedsearches, transforms):
        transform_stanzas = set(transforms.keys()) - {"default"}
        # Also accept standard Splunk lookups that ship with ES
        es_builtin_lookups = {
            "identity_lookup_expanded",
            "asset_lookup_by_str",
            "asset_lookup_by_cidr",
            "cim_corporate_email_domain_lookup",
        }
        allowed = transform_stanzas | es_builtin_lookups
        errors = []
        for name, props in savedsearches.items():
            if name == "default":
                continue
            search = props.get("search", "")
            if not search:
                continue
            refs = extract_lookup_refs(search)
            for ref in refs:
                if ref not in allowed:
                    errors.append(f"[{name}] references undefined lookup `{ref}`")
        assert not errors, "Undefined lookup references:\n" + "\n".join(errors)


class TestRiskJson:
    """Validate that action.risk.param._risk values contain valid JSON."""

    def test_risk_params_are_valid_json(self, savedsearches):
        errors = []
        for name, props in savedsearches.items():
            if name == "default":
                continue
            risk_val = props.get("action.risk.param._risk", "")
            if not risk_val:
                continue
            # Splunk uses $field$ tokens inside JSON — replace with placeholder.
            # Tokens may already be inside quotes ("$risk_score$"), so replace
            # the token itself with a plain string, not a quoted one.
            sanitized = re.sub(r"\$[a-zA-Z_][a-zA-Z0-9_.]*\$", "__PLACEHOLDER__", risk_val)
            try:
                parsed = json.loads(sanitized)
                assert isinstance(parsed, list), "Expected a JSON array"
                for entry in parsed:
                    assert "risk_object_field" in entry, "Missing risk_object_field"
                    assert "risk_object_type" in entry, "Missing risk_object_type"
                    assert "risk_score" in entry, "Missing risk_score"
            except (json.JSONDecodeError, AssertionError) as exc:
                errors.append(f"[{name}] Invalid risk JSON: {exc}")
        assert not errors, "Risk JSON validation errors:\n" + "\n".join(errors)


class TestNoEmptySearches:
    """No savedsearch stanza should have a blank search string."""

    def test_search_not_empty(self, savedsearches):
        errors = []
        for name, props in savedsearches.items():
            if name == "default":
                continue
            search = props.get("search", "").strip()
            if not search:
                errors.append(name)
        assert not errors, f"Stanzas with empty search: {errors}"


class TestSplSemanticGuardrails:
    """Catch common SPL authoring mistakes that delimiter checks miss."""

    def test_missing_pipe_before_eval_after_where(self, savedsearches):
        errors = []
        # Detect cases like: "| where ... eval foo=..."
        bad_pattern = re.compile(r"\|\s*where[^|]*\)\s+eval\s+[a-zA-Z_]")
        for name, props in savedsearches.items():
            if name == "default":
                continue
            search = props.get("search", "")
            if search and bad_pattern.search(search):
                errors.append(name)
        assert not errors, (
            "Searches with probable missing pipe before eval after where:\n"
            + "\n".join(errors)
        )

    def test_no_root_endpoint_datamodel_in_tstats(self, savedsearches):
        errors = []
        # tstats should reference a concrete object (e.g., Endpoint.Processes)
        bad_pattern = re.compile(r"\|\s*tstats\b[^|]*\bfrom\s+datamodel=Endpoint(?:\s|\|)", re.IGNORECASE)
        for name, props in savedsearches.items():
            if name == "default":
                continue
            search = props.get("search", "")
            if search and bad_pattern.search(search):
                errors.append(name)
        assert not errors, (
            "Searches using datamodel=Endpoint without object in tstats:\n"
            + "\n".join(errors)
        )


class TestLookupDrivenCriticalDetections:
    """Guardrails for high-priority detections that must stay lookup-driven."""

    @staticmethod
    def _get_search_by_detection_id(savedsearches: dict[str, dict[str, str]], detection_id: str) -> str:
        for name, props in savedsearches.items():
            if detection_id in name:
                return props.get("search", "")
        return ""

    def test_ai_030_uses_prompt_pattern_lookup(self, savedsearches):
        spl = self._get_search_by_detection_id(savedsearches, "AI-030")
        assert spl, "Could not find search SPL for AI-030"
        assert (
            "inputlookup ai_prompt_injection_patterns" in spl
            or "`ai_prompt_injection_patterns_enabled`" in spl
        ), "AI-030 must use ai_prompt_injection_patterns lookup as pattern source"

    def test_ai_033_uses_api_key_pattern_lookup(self, savedsearches):
        spl = self._get_search_by_detection_id(savedsearches, "AI-033")
        assert spl, "Could not find search SPL for AI-033"
        assert (
            "inputlookup ai_api_key_patterns" in spl
            or "`ai_api_key_patterns_enabled`" in spl
        ), "AI-033 must use ai_api_key_patterns lookup as pattern source"

    def test_ai_034_avoids_unbounded_process_wildcard(self, savedsearches):
        spl = self._get_search_by_detection_id(savedsearches, "AI-034")
        assert spl, "Could not find search SPL for AI-034"
        assert "Processes.process_name=*" not in spl, (
            "AI-034 must not scan Endpoint.Processes with unbounded "
            "Processes.process_name=* wildcard"
        )

    def test_health_searches_use_configured_email_token(self, savedsearches):
        health_stanzas = [
            (name, props) for name, props in savedsearches.items()
            if "Health -" in name
        ]
        assert health_stanzas, "No health stanzas found"
        for name, props in health_stanzas:
            search = props.get("search", "")
            email_to = props.get("action.email.to", "")
            assert "alert_email_to" in search, f"[{name}] must load alert_email_to from ai_detection_config"
            assert email_to == "$result.alert_email_to$", (
                f"[{name}] action.email.to must use $result.alert_email_to$ token"
            )


# ---------------------------------------------------------------------------
# Tstats / Lookup sync helpers
# ---------------------------------------------------------------------------


def _extract_tstats_in_values(spl: str, field_name: str) -> set[str]:
    """Extract values from ``field_name IN ("v1","v2",...)`` in SPL.

    Returns a set of lowercase strings.
    """
    pattern = re.compile(
        rf'{re.escape(field_name)}\s+IN\s*\(([^)]+)\)',
        re.IGNORECASE,
    )
    values: set[str] = set()
    for m in pattern.finditer(spl):
        raw = m.group(1)
        for item in re.findall(r'"([^"]*)"', raw):
            values.add(item.lower())
    return values


# ---------------------------------------------------------------------------
# Tstats / Lookup sync tests
# ---------------------------------------------------------------------------


class TestTstatsLookupSync:
    """Ensure hardcoded tstats IN() lists stay in sync with lookup CSVs.

    The highest-risk maintenance failure mode is when hardcoded process or
    domain lists in tstats queries diverge from the authoritative lookup CSVs.
    Every value in a tstats IN() list **must** exist in the corresponding CSV;
    if it does not, the detection references a process/domain that has no
    lookup enrichment and may produce incomplete or misleading results.
    """

    def _get_search_by_detection_id(
        self, savedsearches: dict[str, dict[str, str]], detection_id: str
    ) -> str:
        """Return the ``search`` SPL for a detection stanza matching *detection_id*."""
        for name, props in savedsearches.items():
            if detection_id in name:
                return props.get("search", "")
        return ""

    # -- Test 1: AI CLI process names (AI-004 / AI-008) ---------------------

    def test_cli_process_names_in_csv(self, savedsearches, tool_processes):
        """AI-004/AI-008 tstats process names must exist in ai_tool_processes.csv (cli)."""
        csv_cli = {
            row["process_name_lc"].lower()
            for row in tool_processes
            if row.get("usage_type") == "cli" and row.get("enabled") == "1"
        }
        errors: list[str] = []
        for det_id in ("AI-004", "AI-008"):
            spl = self._get_search_by_detection_id(savedsearches, det_id)
            assert spl, f"Could not find search SPL for {det_id}"
            tstats_procs = _extract_tstats_in_values(spl, "Processes.process_name")
            not_in_csv = tstats_procs - csv_cli
            if not_in_csv:
                errors.append(
                    f"[{det_id}] tstats has process names not in "
                    f"ai_tool_processes.csv (cli, enabled=1): {sorted(not_in_csv)}"
                )
        assert not errors, (
            "CLI process name drift detected:\n" + "\n".join(errors)
        )

    # -- Test 2: AI desktop app process names (AI-005) ----------------------

    def test_desktop_app_process_names_in_csv(self, savedsearches, tool_processes):
        """AI-005 tstats process names must exist in ai_tool_processes.csv (desktop_app)."""
        csv_desktop = {
            row["process_name_lc"].lower()
            for row in tool_processes
            if row.get("usage_type") == "desktop_app" and row.get("enabled") == "1"
        }
        spl = self._get_search_by_detection_id(savedsearches, "AI-005")
        assert spl, "Could not find search SPL for AI-005"
        tstats_procs = _extract_tstats_in_values(spl, "Processes.process_name")
        not_in_csv = tstats_procs - csv_desktop
        assert not not_in_csv, (
            f"[AI-005] tstats has process names not in "
            f"ai_tool_processes.csv (desktop_app, enabled=1): {sorted(not_in_csv)}"
        )

    # -- Test 3: Local LLM process names (AI-011) --------------------------

    def test_local_llm_process_names_in_csv(self, savedsearches, tool_processes):
        """AI-011 tstats process names must exist in ai_tool_processes.csv (local_llm)."""
        csv_local_llm = {
            row["process_name_lc"].lower()
            for row in tool_processes
            if row.get("usage_type") == "local_llm" and row.get("enabled") == "1"
        }
        spl = self._get_search_by_detection_id(savedsearches, "AI-011")
        assert spl, "Could not find search SPL for AI-011"
        tstats_procs = _extract_tstats_in_values(spl, "Processes.process_name")
        not_in_csv = tstats_procs - csv_local_llm
        assert not not_in_csv, (
            f"[AI-011] tstats has process names not in "
            f"ai_tool_processes.csv (local_llm, enabled=1): {sorted(not_in_csv)}"
        )

    # -- Test 4: DNS domain sync (AI-012) -----------------------------------

    def test_dns_domains_in_csv(self, savedsearches, provider_domains):
        """AI-012 tstats DNS domains must exist in ai_provider_domains.csv."""
        csv_domains = {
            row["domain"].lower()
            for row in provider_domains
            if row.get("enabled") == "1"
        }
        spl = self._get_search_by_detection_id(savedsearches, "AI-012")
        assert spl, "Could not find search SPL for AI-012"
        tstats_domains = _extract_tstats_in_values(spl, "DNS.query")
        not_in_csv = tstats_domains - csv_domains
        assert not not_in_csv, (
            f"[AI-012] tstats has DNS domains not in "
            f"ai_provider_domains.csv (enabled=1): {sorted(not_in_csv)}"
        )

    # -- Test 5: Web API domain sync (AI-006) -------------------------------

    def test_api_domains_in_csv(self, savedsearches, provider_domains):
        """AI-006 tstats API domains must exist in ai_provider_domains.csv (api)."""
        csv_api_domains = {
            row["domain"].lower()
            for row in provider_domains
            if row.get("usage_type") == "api" and row.get("enabled") == "1"
        }
        spl = self._get_search_by_detection_id(savedsearches, "AI-006")
        assert spl, "Could not find search SPL for AI-006"
        tstats_domains = _extract_tstats_in_values(spl, "Web.url_domain")
        not_in_csv = tstats_domains - csv_api_domains
        assert not not_in_csv, (
            f"[AI-006] tstats has API domains not in "
            f"ai_provider_domains.csv (api, enabled=1): {sorted(not_in_csv)}"
        )

    # -- Test 6: Agent framework sync (AI-037 / AI-039) ---------------------

    def test_agent_framework_process_names_sync(self, savedsearches):
        """AI-039 parent_process_name list must be a superset of AI-037 process_name list."""
        spl_037 = self._get_search_by_detection_id(savedsearches, "AI-037")
        spl_039 = self._get_search_by_detection_id(savedsearches, "AI-039")
        assert spl_037, "Could not find search SPL for AI-037"
        assert spl_039, "Could not find search SPL for AI-039"
        procs_037 = _extract_tstats_in_values(spl_037, "Processes.process_name")
        parents_039 = _extract_tstats_in_values(spl_039, "Processes.parent_process_name")
        # AI-039 detects autonomous actions from agent frameworks, so its parent list
        # should match the process list from AI-037 (agent execution detection)
        not_in_039 = procs_037 - parents_039
        assert not not_in_039, (
            f"AI-037 process names not in AI-039 parent list: {sorted(not_in_039)}"
        )
