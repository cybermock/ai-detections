"""SPL references resolve inside the package's prereq closure, and every search renders cleanly."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

import pytest

from .conftest import (
    MACRO_RE,
    PACKAGES_DIR,
    closure_macros,
    drilldown_searches_text,
    expand_macros,
    load_lookups,
    package_closure,
    parse_outputs,
    read_conf,
    render,
    repo_macro_names,
    rls,
    savedsearches,
    search_packages,
    split_args,
)

# Macros supplied by Enterprise Security / Splunk_SA_CIM rather than this repo.
ES_MACRO_NAMES = {"drop_dm_object_name", "security_content_ctime", "notable", "risk_index"}
ES_MACRO_PREFIXES = ("cim_", "get_")
ES_LOOKUPS = {"identity_lookup_expanded", "asset_lookup_by_str", "asset_lookup_by_cidr"}

LOOKUP_CMD_RE = re.compile(
    r"(?:^|[|\[])\s*(?P<cmd>inputlookup|lookup)\s+(?:[A-Za-z_]+\s*=\s*\S+\s+)*(?P<name>[A-Za-z0-9_.\-]+)",
    re.IGNORECASE,
)
PIPE_EMPTY_PARENS_RE = re.compile(r"\|\s*\(\s*\)")
QUOTED_RE = re.compile(r'"(?:[^"\\]|\\.)*"')


def _is_es_macro(name: str) -> bool:
    return name in ES_MACRO_NAMES or name.startswith(ES_MACRO_PREFIXES)


def _spl_blocks(package: str) -> list[tuple[str, str]]:
    """(label, spl) for every saved search and drilldown search of a package."""
    blocks = []
    for stanza, kv in savedsearches(package).items():
        if "search" not in kv:
            continue
        blocks.append((f"[{stanza}] search", kv["search"]))
        for i, dd in enumerate(drilldown_searches_text(kv)):
            blocks.append((f"[{stanza}] drilldown {i}", dd))
    return blocks


def _closure_lookup_names(package: str) -> set[str]:
    names: set[str] = set()
    for pkg in package_closure(package):
        for stanza in read_conf(PACKAGES_DIR / pkg / "confs" / "transforms.conf"):
            names.add(stanza)
        for csv_path in (PACKAGES_DIR / pkg / "lookups").glob("*.csv"):
            names.update({csv_path.name, Path(csv_path.name).stem})
    return names


@pytest.mark.parametrize("package", search_packages())
def test_macros_resolve_in_closure(package):
    macros = closure_macros(package)
    errors = []
    for label, spl in _spl_blocks(package):
        expanded = expand_macros(spl, macros)
        for m in MACRO_RE.finditer(expanded):
            name, argtext = m.group(1), m.group(2)
            if _is_es_macro(name):
                continue
            arity = 0 if argtext is None else len(split_args(argtext))
            if name in repo_macro_names():
                errors.append(f"{label}: `{name}` ({arity} args) is defined in the repo but not in this "
                              f"package's prereq closure {package_closure(package)} with that arity")
            else:
                errors.append(f"{label}: `{name}` ({arity} args) is not defined anywhere and not an ES/CIM macro")
    assert not errors, f"{package}: " + "; ".join(sorted(set(errors)))


@pytest.mark.parametrize("package", search_packages())
def test_lookups_resolve_in_closure(package):
    macros = closure_macros(package)
    known = _closure_lookup_names(package) | ES_LOOKUPS
    errors = []
    for label, spl in _spl_blocks(package):
        for m in LOOKUP_CMD_RE.finditer(expand_macros(spl, macros)):
            if m.group("name") not in known:
                errors.append(f"{label}: `{m.group('cmd')} {m.group('name')}` has no CSV/transforms stanza in the "
                              "prereq closure and is not an ES lookup")
    assert not errors, f"{package}: " + "; ".join(sorted(set(errors)))


@pytest.mark.parametrize("package", search_packages())
def test_lookup_fields_exist(package):
    """Key and OUTPUT fields of every repo lookup call must be columns of the CSV."""
    lookups = load_lookups(package_closure(package))
    macros = closure_macros(package)
    errors = []
    for label, spl in _spl_blocks(package):
        for m in rls.LOOKUP_RE.finditer(expand_macros(spl, macros)):
            name = m.group("name")
            if name not in lookups:
                continue  # unresolved lookups are reported by test_lookups_resolve_in_closure
            header = set(next(csv.reader(lookups[name].splitlines()), []))
            wanted = [m.group("key")] + [src for src, _ in parse_outputs(m.group("outputs"))]
            missing = sorted({f for f in wanted if f not in header})
            if missing:
                errors.append(f"{label}: `lookup {name}` uses field(s) {missing} that are not CSV columns")
    assert not errors, f"{package}: " + "; ".join(sorted(set(errors)))


@pytest.mark.parametrize("package", search_packages())
def test_rendered_search_is_clean(package):
    try:
        rendered = render(package, drilldowns=True)
    except (ValueError, json.JSONDecodeError):
        rendered = render(package, drilldowns=False)  # malformed drilldown JSON is reported elsewhere
    assert rendered, f"{package}: render_live_spl produced nothing"
    errors = []
    for r in rendered:
        label = f"[{r['stanza']}] {r['kind']}"
        leftovers = sorted({m.group(1) for m in MACRO_RE.finditer(r["spl"]) if m.group(1) in repo_macro_names()})
        if leftovers:
            errors.append(f"{label}: unexpanded repo macro(s) {leftovers}")
        if PIPE_EMPTY_PARENS_RE.search(r["spl"]):
            errors.append(f"{label}: renders '| ()' (a piped empty filter macro)")
    assert not errors, f"{package}: " + "; ".join(errors)


# ---------------------------------------------------------------------------
# Delimiters and common authoring mistakes
# ---------------------------------------------------------------------------


def _balanced(text: str, open_ch: str, close_ch: str) -> str | None:
    depth, in_dq, escaped = 0, False, False
    for ch in text:
        if in_dq and escaped:
            escaped = False  # this character is escaped (handles "\\" before a closing quote)
            continue
        if in_dq and ch == "\\":
            escaped = True
        elif ch == '"':
            in_dq = not in_dq
        elif not in_dq:
            if ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth < 0:
                    return f"extra '{close_ch}'"
    if in_dq:
        return "unterminated double quote"
    if depth:
        return f"{depth} unclosed '{open_ch}'"
    return None


@pytest.mark.parametrize("package", search_packages())
def test_balanced_delimiters(package):
    errors = []
    for label, spl in _spl_blocks(package):
        for open_ch, close_ch in (("(", ")"), ("[", "]")):
            problem = _balanced(spl, open_ch, close_ch)
            if problem:
                errors.append(f"{label}: {problem}")
    assert not errors, f"{package}: " + "; ".join(sorted(set(errors)))


@pytest.mark.parametrize("package", search_packages())
def test_spl_guardrails(package):
    missing_pipe = re.compile(r"\|\s*where[^|]*\)\s+eval\s+[a-zA-Z_]")
    root_endpoint = re.compile(r"\|\s*tstats\b[^|]*\bfrom\s+datamodel=Endpoint(?:\s|\|)", re.IGNORECASE)
    double_pipe = re.compile(r"\|\s*\|")
    errors = []
    for label, spl in _spl_blocks(package):
        expanded = QUOTED_RE.sub('""', expand_macros(spl, closure_macros(package)))
        if missing_pipe.search(spl):
            errors.append(f"{label}: probable missing pipe before eval after where")
        if root_endpoint.search(spl):
            errors.append(f"{label}: tstats uses datamodel=Endpoint without a dataset (e.g. Endpoint.Processes)")
        if double_pipe.search(expanded):
            errors.append(f"{label}: macro expansion yields a double pipe '| |'")
    assert not errors, f"{package}: " + "; ".join(errors)
