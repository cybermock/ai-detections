# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "loguru",
#     "jsonschema",
#     "pyyaml",
#     "addonfactory-splunk-conf-parser-lib",
# ]
# ///
import os

import yaml
import addonfactory_splunk_conf_parser_lib
from loguru import logger
import os
import json
import glob
import subprocess

MITRE_BY_PACKAGE_ID = {}
SEARCHES_BY_PACKAGE_ID = {}


def update_globals(package_id: str, conf_dict: dict):
    """
    Given a conf dict representing savedsearches.conf from a package, pull out all
    MITRE annotations and collect them in MITRE_BY_PACKAGE_ID, and collect all search
    names into SEARCHES_BY_PACKAGE_ID.
    """
    for stanza in conf_dict.keys():
        if package_id in SEARCHES_BY_PACKAGE_ID:
            SEARCHES_BY_PACKAGE_ID[package_id].append(stanza)
        else:
            SEARCHES_BY_PACKAGE_ID[package_id] = [stanza]
        if "action.correlationsearch.annotations" in conf_dict[stanza]:
            annotations = json.loads(
                conf_dict[stanza]["action.correlationsearch.annotations"]
            )
            mitre_annotations = annotations.get("mitre_attack")
            existing_annotations = MITRE_BY_PACKAGE_ID.get(package_id, [])
            combined = list(set(mitre_annotations + existing_annotations))
            MITRE_BY_PACKAGE_ID[package_id] = combined


def compile_package(
    package_id: str, package_path: str
) -> dict:
    """
    Given a path to a package and some of its metadata, add its conf files and views
    to a dictionary which will eventually by JSON-dumped. Format looks like this:
    {"confs":
        {"savedsearches":
            {"HDSI - ES - Alerting":
                {"cron_schedule": "* * * * *",
            ...
     "views":
        {"my_view": "big-ass blob of xml"}
    }

    """
    compiled = {"confs": {}, "views": {}}
    for conf_file_path in glob.glob(os.path.join(package_path, "confs", "*.conf")):
        file_type = conf_file_path.split("/")[-1].split(".conf")[0]
        parser = addonfactory_splunk_conf_parser_lib.TABConfigParser()
        parser.read(conf_file_path)
        compiled["confs"][file_type] = parser.item_dict()
        if file_type == "savedsearches":
            update_globals(
                package_id=package_id, conf_dict=compiled["confs"][file_type]
            )

    for view_file_path in glob.glob(os.path.join(package_path, "views", "*.xml")):
        view_name = file_type = view_file_path.split("/")[-1].split(".xml")[0]

        with open(view_file_path, "r") as f:
            compiled["views"][view_name] = f.read()
    return compiled 


def discover_packages(basedir="packages"):
    """Iterator which yields paths to packages"""
    for root, dirs, files in os.walk(basedir):
        for d in dirs:
            if not os.path.isfile(os.path.join(root, d, "package.yml")):
                continue
            # Package ID, package path
            yield d, os.path.join(root, d)


def main():
    stage = os.environ.get("STAGE", "dev")
    catalog_bucket = f"hlcu-api-{stage}-catalog-bucket"
    package_bucket = f"hlcu-api-{stage}-bucket"

    # Make working dirs if they don't exist
    working_dir = os.path.join(os.sep, "tmp", "deploy_socrepo")
    if not os.path.isdir(working_dir):
        os.makedirs(working_dir)
    package_output_dir = os.path.join(working_dir, "output_packages")
    catalog_output_dir = os.path.join(working_dir, "output_catalogs")
    if not os.path.isdir(package_output_dir):
        os.makedirs(package_output_dir)
    if not os.path.isdir(catalog_output_dir):
        os.makedirs(catalog_output_dir)

    all_packages = {}
    all_public_packages = {}

    for package_id, package_path in discover_packages(basedir="packages"):
        yml_path = os.path.join(package_path, "package.yml")
        with open(yml_path, "r") as f:
            package = yaml.safe_load(f)

        # Update catalogs
        all_packages[package_id] = package
        if not package.get("is_hl_only", False):
            all_public_packages[package_id] = package

        # Build package dicts
        version = package["version"]
        compiled = compile_package(package_id, package_path)
        filename = f"{package_id}_{version}.json"
        with open(os.path.join(package_output_dir, filename), "w") as f:
            json.dump(compiled, f)

        all_packages[package_id]["mitre_annotations"] = MITRE_BY_PACKAGE_ID.get(
            package_id, []
        )
        all_packages[package_id]["searches"] = SEARCHES_BY_PACKAGE_ID.get(
            package_id, []
        )
    with open(os.path.join(catalog_output_dir, "catalog.json"), "w") as f:
        json.dump(all_packages, f)
    
    with open(os.path.join(catalog_output_dir, "public_catalog.json"), "w") as f:
        json.dump(all_public_packages, f)

    subprocess.run(["aws", "s3", "sync", package_output_dir, f"s3://{package_bucket}"])
    subprocess.run(["aws", "s3", "sync", catalog_output_dir, f"s3://{catalog_bucket}"])


if __name__ == "__main__":
    main()
