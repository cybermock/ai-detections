# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "loguru",
#     "jsonschema",
#     "pyyaml",
#     "addonfactory-splunk-conf-parser-lib",
# ]
# ///
import csv
import glob
import os
import sys
import re

import addonfactory_splunk_conf_parser_lib
import yaml
from jsonschema import validate
from jsonschema.exceptions import ValidationError
from loguru import logger

with open("package-schema.yml", "r") as f:
    schema = yaml.safe_load(f)


def get_package_dependencies(package_id: str, catalog: dict, dependencies: list):
    """
    Recursive function which will return a list of all package_ids the <package_id>
    depends on. This includes <package_id> itself.
    """
    package_metadata = catalog[package_id]
    dependencies.append(package_id)
    if "prereq_packages" in package_metadata:
        for prereq in package_metadata["prereq_packages"]:
            if prereq not in dependencies:
                dependencies = get_package_dependencies(
                    package_id=prereq, catalog=catalog, dependencies=dependencies
                )
    return dependencies


def discover_packages(basedir="packages"):
    """Iterator which yields paths to packages"""
    for root, dirs, files in os.walk(basedir):
        for d in dirs:
            if not os.path.isfile(os.path.join(root, d, "package.yml")):
                continue
            # Package ID, package path
            yield d, os.path.join(root, d)

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

    for view_file_path in glob.glob(os.path.join(package_path, "views", "*.xml")):
        view_name = file_type = view_file_path.split("/")[-1].split(".xml")[0]

        with open(view_file_path, "r") as f:
            compiled["views"][view_name] = f.read()
    return compiled 


def load_allowed_tags(csv_path: str) -> set:
    """Load allowed tags from package_tags.csv (expects header: tag,count)."""
    if not os.path.isfile(csv_path):
        logger.error(
            f"Tags file not found: {csv_path}. Generate it with: python3 tools/collect_tags.py"
        )
        sys.exit(1)
    allowed = set()
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f,  fieldnames=['tag', 'count'])
        for row in reader:
            allowed.add(row['tag'].strip())
    return allowed


def main():
    catalog = {}
    allowed_tags = load_allowed_tags("package_tags.csv")
    for package_id, package_path in discover_packages(basedir="packages"):
        yml_path = os.path.join(package_path, "package.yml")
        with open(yml_path, "r") as f:
            package = yaml.safe_load(f)
        try:
            validate(package, schema)
        except ValidationError as e:
            logger.exception("Error validating %s" % package_id)
            sys.exit(1)
        # Validate that all tags are in the allowed list
        pkg_tags = package.get("tags", []) or []
        if not isinstance(pkg_tags, list):
            logger.error(
                f"Package {package_id} has non-list 'tags' field; expected a list of strings."
            )
            sys.exit(1)
        missing = sorted({str(t).strip() for t in pkg_tags if str(t).strip() and str(t).strip() not in allowed_tags})
        if missing:
            logger.error(
                f"Package {package_id} contains unknown tag(s) not in package_tags.csv: {', '.join(missing)}"
            )
            sys.exit(1)
        try:
            _compiled = compile_package(package_id, package_path)
        except Exception:
            logger.exception("Error validating %s" % package_id)
            sys.exit(1)
        catalog[package_id] = package

    # Check to make sure all defined dependencies actually exist.
    for package_id in catalog.keys():
        try:
            deps = []
            get_package_dependencies(package_id, catalog, deps)
        except KeyError as key_e:
            missing_key = key_e.args[0]
            logger.error(
                "Failed to find dependency in package %s. Package %s does not exist."
                % (package_id, missing_key)
            )
            sys.exit(1)

    # Check to make sure no conf files have unresolved escapes
    conf_files = glob.glob("packages/**/confs/*.conf")
    for filename in conf_files:
        with open(filename, "r") as f:
            last_line = f.readlines()[-1]
            if last_line.rstrip().endswith("\\"):
                logger.error("Conf file %s has an unresolved backslash at the end of the file." % filename)
                sys.exit(1)

    # Check to make sure no conf files have leading or trailing spaces in stanza definitions
    stanza_pattern = re.compile(r'^\[(.+?)\]\s*$')
    for filename in conf_files:
        with open(filename, "r") as f:
            for line in f.readlines():
                line = line.strip()
                if not stanza_pattern.match(line):
                    continue
                if line.startswith("[ ") or line.endswith(" ]"):
                    logger.error("Conf file %s has a leading or trailing space in the stanza definition: \"%s\"" % (filename, line))
                    sys.exit(1)

if __name__ == "__main__":
    main()
