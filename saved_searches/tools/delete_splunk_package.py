#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests",
# ]
#
# ///


import csv
import json
import requests
import sys

client_url = "<splunk-uri-domain-no-https>:8089"

token = "<put your splunk_8443 authorization token here>"
header = {"Authorization": f"Splunk {token}", "Content-Type": "application/json"}

search_id = "https://127.0.0.1:8089/servicesNS/nobody/HurricaneLabsContentPlus/configs/conf-savedsearches/%20Network%20-%20HDSI%20Web%20Directory%20Traversal%20-%20Rule?output_mode=json"

api_url = search_id.replace("127.0.0.1:8089", client_url)

data = {}

r = requests.get(api_url, headers=header, verify=False)
r.raise_for_status()
js = json.loads(r.text).get('entry')[0]
print(f"Deleting search '{js['name']}'")
x = input("would you like to delete this search? (y/n)")
if x == "y":
    r = requests.delete(api_url, headers=header, verify=False)
    if r.status_code == 200: 
        print("yay it worked!")
    r.raise_for_status()
    with open("debug_delete_search.log", "w") as file: 
        file.write(r.text)
    print("See 'debug_delete_search.log' for full delete output")
