"""Package layout and package.yml release conventions."""

from __future__ import annotations

import csv
import re

import pytest

from .conftest import (
    COMMON_DIR,
    COMMON_PACKAGE,
    PACKAGE_TAGS_CSV,
    PACKAGES_DIR,
    RELEASE_VERSION,
    all_packages,
    package_macro_stanzas,
    package_meta,
    role,
    savedsearches,
    search_packages,
)

# CIM 4.x/5.x data models plus the ES-shipped ones. Items may name a dataset ("Endpoint.Processes").
KNOWN_DATAMODELS = {
    "Alerts", "Application_State", "Authentication", "Certificates", "Change", "Change_Analysis",
    "Compute_Inventory", "Data_Access", "Databases", "DLP", "Email", "Endpoint", "Event_Signatures",
    "Interprocess_Messaging", "Intrusion_Detection", "Inventory", "JVM", "Malware", "Network_Resolution",
    "Network_Sessions", "Network_Traffic", "Performance", "Splunk_Audit", "Splunk_CIM_Validation",
    "Ticket_Management", "Updates", "Vulnerabilities", "Web",
    # Enterprise Security data models
    "Risk", "Threat_Intelligence", "Identity_Management", "Assets_And_Identities", "Incident_Management",
    "Domain_Analysis", "Endpoint_Detection_and_Response",
}

TSTATS_DATAMODEL_RE = re.compile(r"\bdatamodel\s*[=:]\s*\"?([A-Za-z_]+)")


@pytest.mark.parametrize("package", all_packages())
def test_required_files(package):
    pkg_dir = PACKAGES_DIR / package
    if package == COMMON_PACKAGE:
        required = ["package.yml", "README.md", "confs/macros.conf", "confs/transforms.conf"]
    else:
        required = ["package.yml", "README.md", "confs/savedsearches.conf", "confs/macros.conf"]
    missing = [rel for rel in required if not (pkg_dir / rel).is_file()]
    assert not missing, f"{package}: missing required file(s) {missing}"
    if package == COMMON_PACKAGE:
        assert any((COMMON_DIR / "lookups").glob("*.csv")), f"{package}: lookups/ has no CSV files"


@pytest.mark.parametrize("package", search_packages())
def test_package_has_savedsearch(package):
    stanzas = {k: v for k, v in savedsearches(package).items() if "search" in v}
    assert stanzas, f"{package}: confs/savedsearches.conf defines no stanza with a search"


@pytest.mark.parametrize("package", all_packages())
def test_package_version(package):
    version = str(package_meta(package).get("version", ""))
    assert version == RELEASE_VERSION, f"{package}: package.yml version is {version!r}, expected {RELEASE_VERSION!r}"


@pytest.mark.parametrize("package", search_packages())
def test_description_starts_with_version(package):
    version = str(package_meta(package).get("version", ""))
    prefix = f"v{version} "
    errors = [
        f"[{stanza}] description starts {kv.get('description', '')[:20]!r}, expected prefix {prefix!r}"
        for stanza, kv in savedsearches(package).items()
        if "search" in kv and not kv.get("description", "").startswith(prefix)
    ]
    assert not errors, f"{package}: " + "; ".join(errors)


@pytest.mark.parametrize("package", all_packages())
def test_required_metadata(package):
    meta = package_meta(package)
    missing = [k for k in ("version", "package_title", "description", "deployment_type") if not meta.get(k)]
    assert not missing, f"{package}: package.yml missing {missing}"
    assert meta["deployment_type"] in {"global_critical", "global", "adhoc"}, (
        f"{package}: deployment_type {meta['deployment_type']!r} not in global_critical/global/adhoc"
    )


@pytest.mark.parametrize("package", search_packages())
def test_prereq_packages_exist(package):
    prereqs = package_meta(package).get("prereq_packages") or []
    missing = [p for p in prereqs if not (PACKAGES_DIR / p / "package.yml").exists()]
    assert not missing, f"{package}: prereq_packages not found under packages/: {missing}"
    assert COMMON_PACKAGE in prereqs, f"{package}: prereq_packages must include {COMMON_PACKAGE}"


def _known_tags() -> set[str]:
    with open(PACKAGE_TAGS_CSV, newline="", encoding="utf-8") as f:
        return {row["tag"].strip() for row in csv.DictReader(f)}


@pytest.mark.parametrize("package", all_packages())
def test_tags_are_registered(package):
    tags = package_meta(package).get("tags") or []
    unknown = sorted(set(tags) - _known_tags())
    assert not unknown, f"{package}: tags not in saved_searches/package_tags.csv: {unknown}"


@pytest.mark.parametrize("package", all_packages())
def test_common_dependencies_resolve(package):
    deps = package_meta(package).get("common_dependencies") or []
    common_macros = set(package_macro_stanzas(COMMON_PACKAGE))
    errors = []
    for dep in deps:
        kind, _, name = str(dep).partition(":")
        if kind == "macros" and name not in common_macros:
            errors.append(f"{dep!r} has no [{name}] stanza in {COMMON_PACKAGE}/confs/macros.conf")
    assert not errors, f"{package}: " + "; ".join(errors)


@pytest.mark.parametrize("package", all_packages())
def test_data_prereq_datamodels_are_cim(package):
    prereqs = package_meta(package).get("data_prereqs") or {}
    items = (prereqs.get("datamodels") or {}).get("items") or []
    unknown = [i for i in items if str(i).split(".")[0] not in KNOWN_DATAMODELS]
    assert not unknown, (
        f"{package}: data_prereqs.datamodels uses non-CIM name(s) {unknown} "
        "(e.g. the CIM data model is 'DLP', not 'Data_Loss_Prevention')"
    )


@pytest.mark.parametrize("package", search_packages())
def test_search_datamodels_are_cim(package):
    errors = []
    for stanza, kv in savedsearches(package).items():
        for dm in TSTATS_DATAMODEL_RE.findall(kv.get("search", "")):
            if dm not in KNOWN_DATAMODELS:
                errors.append(f"[{stanza}] datamodel {dm!r}")
    assert not errors, f"{package}: search references non-CIM data model(s): " + "; ".join(errors)


@pytest.mark.parametrize("package", all_packages())
def test_package_name_prefix(package):
    assert role(package) in {"common", "health", "aggregator", "hunting", "detection"}
    assert package.startswith(("hdsi_ai_", "hdsi_rba_ai_")), f"{package}: unexpected package name prefix"
