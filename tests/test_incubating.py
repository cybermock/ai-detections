"""Incubating packages stay renderable, stay unreleased, and nothing released depends on them.

``saved_searches/incubating/`` holds detections proven only with synthetic test events. They are
kept out of ``saved_searches/packages/`` so validate.py, deploy.py and the release tests never
treat them as release content, but they must keep working against the current common package
so they can be promoted later.
"""

from __future__ import annotations

import re

import pytest

from .conftest import MACRO_RE, PACKAGES_DIR, all_packages, package_closure, read_conf, render, rls

INCUBATING_DIR = rls.INCUBATING_DIR
PIPE_EMPTY_PARENS_RE = re.compile(r"\|\s*\(\s*\)")


def incubating_packages() -> list[str]:
    if not INCUBATING_DIR.is_dir():
        return []
    return sorted(p.name for p in INCUBATING_DIR.iterdir() if p.is_dir() and (p / "package.yml").exists())


def test_incubating_readme_present():
    assert (INCUBATING_DIR / "README.md").exists(), "saved_searches/incubating/README.md explains the folder"


@pytest.mark.parametrize("package", incubating_packages())
def test_incubating_layout(package):
    root = INCUBATING_DIR / package
    for rel in ("package.yml", "README.md", "RUNBOOK.md", "confs/savedsearches.conf", "confs/macros.conf"):
        assert (root / rel).exists(), f"{package}: missing {rel}"


@pytest.mark.parametrize("package", incubating_packages())
def test_incubating_not_also_released(package):
    assert not (PACKAGES_DIR / package).exists(), f"{package} is in both packages/ and incubating/"


@pytest.mark.parametrize("package", incubating_packages())
def test_incubating_readme_says_so(package):
    for doc in ("README.md", "RUNBOOK.md"):
        text = (INCUBATING_DIR / package / doc).read_text(encoding="utf-8")
        assert "incubating" in text.lower(), f"{package}/{doc} does not say the package is incubating (unreleased)"


@pytest.mark.parametrize("package", incubating_packages())
def test_incubating_prereqs_are_released(package):
    others = [p for p in package_closure(package) if p != package]
    unreleased = [p for p in others if not (PACKAGES_DIR / p).is_dir()]
    assert not unreleased, f"{package}: prereq_packages not in packages/: {unreleased}"


@pytest.mark.parametrize("package", incubating_packages())
def test_incubating_renders_cleanly(package):
    items = render(package, drilldowns=True)
    assert items, f"{package}: nothing rendered"
    for item in items:
        spl = item["spl"]
        leftover = [m.group(1) for m in MACRO_RE.finditer(spl) if m.group(1).startswith(("hdsi_", "ai_"))]
        assert not leftover, f"{package} {item['kind']}: repo macros did not expand: {sorted(set(leftover))}"
        assert not PIPE_EMPTY_PARENS_RE.search(spl), f"{package} {item['kind']}: piped empty macro `| ()`"


def test_released_packages_do_not_depend_on_incubating():
    incubating = set(incubating_packages())
    problems = []
    for pkg in all_packages():
        deps = incubating.intersection(package_closure(pkg))
        if deps:
            problems.append(f"{pkg}: prereq_packages include incubating {sorted(deps)}")
        for conf in ("savedsearches.conf", "macros.conf"):
            for stanza, kv in read_conf(PACKAGES_DIR / pkg / "confs" / conf).items():
                for key, value in kv.items():
                    if key == "description":
                        continue
                    for m in MACRO_RE.finditer(value):
                        if any(m.group(1).startswith(f"{inc}_") for inc in incubating):
                            problems.append(f"{pkg} {conf} [{stanza}] {key}: calls incubating macro `{m.group(1)}`")
    assert not problems, "\n".join(problems)
