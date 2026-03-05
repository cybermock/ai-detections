# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "httpx",
#     "pyyaml",
#     "addonfactory-splunk-conf-parser-lib",
#     "loguru",
# ]
# ///

import json
import os
import time
import yaml
import asyncio
from typing import Dict, Any, List, Tuple
import addonfactory_splunk_conf_parser_lib
import httpx
from loguru import logger
from httpx import AsyncHTTPTransport

# Configuration
API_ENDPOINT = "https://exthec.splunkcloud.io/services/collector/event"
SPLUNK_HEC_TOKEN = os.environ[
    "SPLUNK_HEC_TOKEN"
]  # In production, load from environment variable
HEADERS = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"}


async def process_package(
    client: httpx.AsyncClient, package_id: str, package_path: str
) -> None:
    """
    Process a single package and send it to the API endpoint.
    """
    # Read package metadata
    yml_path = os.path.join(package_path, "package.yml")
    with open(yml_path, "r") as f:
        package_meta = yaml.safe_load(f)

    # Find and process savedsearches.conf
    searches = []
    conf_file_path = os.path.join(package_path, "confs", "savedsearches.conf")
    if os.path.exists(conf_file_path):
        parser = addonfactory_splunk_conf_parser_lib.TABConfigParser()
        parser.read(conf_file_path)
        conf_dict = parser.item_dict()

        # Extract search strings from each stanza
        for stanza, content in conf_dict.items():
            if "search" in content:
                if "action.correlationsearch.annotations" in content:
                    annotations = json.loads(content["action.correlationsearch.annotations"])
                else:
                    annotations = {}

                mitre_attack = annotations.get("mitre_attack", {})

                description = content.get("description", "")
                rule_name = content.get("action.correlationsearch.label", "")
                searches.append(
                    {
                        "title": stanza,
                        "search": content["search"].replace("\\\n", "\n"),
                        "description": description,
                        "mitre_attack": mitre_attack,
                        "rule_name": rule_name,
                    }
                )

    # Combine metadata and searches
    data = {"package_id": package_id, "metadata": package_meta, "searches": searches}

    payload = {
        "time": int(time.time()),
        "host": "code.hurricanelabs.net",
        "source": "es_correlation_searches",
        "sourcetype": "hlcp:repo:hec",
        "event": data,
    }

    try:
        response = await client.post(API_ENDPOINT, json=payload)
        response.raise_for_status()
    except httpx.HTTPError as e:
        logger.error(f"Failed to send package {package_id}: {str(e)}")


def discover_packages(basedir="packages") -> List[Tuple[str, str]]:
    """Iterator which yields paths to packages"""
    packages = []
    for root, dirs, files in os.walk(basedir):
        for d in dirs:
            if not os.path.isfile(os.path.join(root, d, "package.yml")):
                continue
            packages.append((d, os.path.join(root, d)))
    return packages


async def main():
    packages = discover_packages()

    transport = AsyncHTTPTransport(retries=3)

    async with httpx.AsyncClient(
        headers=HEADERS,
        timeout=30.0,
        limits=httpx.Limits(max_connections=10),
        transport=transport,
    ) as client:
        tasks = [
            process_package(client, package_id, package_path)
            for package_id, package_path in packages
        ]
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
