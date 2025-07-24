#!/usr/bin/env python3
from datetime import datetime

import logging
import sys

import requests


LOGGER = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s -- %(message)s", "%H:%M:%S"))
LOGGER.addHandler(handler)
LOGGER.setLevel(logging.DEBUG)

responder_name = "Gatewatcher_CTI_Identity_1_0"

# Variables to modify with your information
# TheHive
theHive_fqdn = "xxxxxxxxxxxx"
theHive_api_key = "xxxxxxxxxxxx"
theHive_headers = {"Authorization": f"Bearer {theHive_api_key}", "Content-Type": "application/json"}

# Cortex
cortex_fqdn = "xxxxxxxxxx"
cortex_api_key = "xxxxxxxxx"
cortex_header = {"Authorization": f"Bearer {cortex_api_key}"}

# Responder conf
responder_conf = {
    "name": f"{responder_name}",
    "configuration": {
        "LISApiKey": "xxxxxxxx",
        "theHiveApiKey": f"{theHive_api_key}",
        "theHiveFQDN": "xxxxxxxxxx",
        "jobTimeout": 15,
        "check_tlp": True,
        "max_tlp": 2,
        "check_pap": True,
        "max_pap": 2,
    },
    "jobTimeout": 15,
}


def cortex_enable_responder(conf: dict[str, any]):
    response = requests.post(
        url=f"{cortex_fqdn}/api/organization/responder/{responder_name}", headers=cortex_header, json=conf
    )
    if response.status_code != 201:
        LOGGER.error(f"Cannot set the responder: {response.content}")
    return response.json()


def cortex_list_enabled_responder():
    response = requests.get(url=f"{cortex_fqdn}/api/responder", headers=cortex_header)
    if response.status_code != 200:
        LOGGER.error(f"Cannot list enabled responder: {response.content}")
    return response.json()


def cortex_desable_responder(responder_id: str):
    response = requests.delete(url=f"{cortex_fqdn}/api/organization/responder/{responder_id}", headers=cortex_header)
    if response.status_code != 204:
        LOGGER.error(f"Cannot desable the responder: {response.content}")
    return response.json()


def cortex_update_responder_conf(conf: dict[str, any], responder_id: str):
    response = requests.patch(url=f"{cortex_fqdn}/api/responder/{responder_id}", headers=cortex_header, json=conf)
    if response.status_code != 200:
        LOGGER.error(f"Cannot update the responder configuration : {response.content}")
    return response.json()


def thehive_create_case(domain_name: str):
    date = datetime.utcnow()
    response = requests.post(
        url=f"{theHive_fqdn}/api/v1/case",
        headers=theHive_headers,
        json={
            "title": f": {date} - {domain_name}",
            "description": f"This case contents informations about leaked mails for the {domain_name} domain",
        },
    )
    if response.status_code != 201:
        LOGGER.error("Error: Cannot create the case")
    result = response.json()
    return result


def thehive_delete_case(case_id: str):
    response = requests.delete(url=f"{theHive_fqdn}/api/v1/case/{case_id}", headers=theHive_headers)
    if response.status_code != 204:
        LOGGER.error(f"Error: Cannot delete '{case_id}' case: {response.status_code}. {response.text}")


def thehive_list_case_responders(case_id: str) -> list[dict]:
    """Get list of runnable responders for a specific case"""

    response = requests.get(
        url=f"{theHive_fqdn}/api/connector/cortex/responder/case/{case_id}", headers=theHive_headers
    )
    if response.status_code != 200:
        LOGGER.error(
            f"Error: Cannot retrieve responders list for '{case_id}' case: {response.status_code}. {response.text}"
        )
    return response.json()


def run_responder():
    # Check arguments
    nb_args = len(sys.argv)
    if nb_args != 3:
        LOGGER.error(
            "Cannot run this script, number of argument is wrong ! (Only two arguments)\n Please use this format:\n - python3 path/to/the/script.py domain_name minutes"  # noqa: E501
        )
        return
    domain_name = sys.argv[1]
    minutes = int(sys.argv[2])
    responder_conf["configuration"]["domain"] = domain_name
    responder_conf["configuration"]["minutes"] = minutes

    # Check if the responder is enabled
    cortex_responders = cortex_list_enabled_responder()
    cortex_responder = None
    for r in cortex_responders:
        if r.get("name") == responder_name:
            cortex_responder = r
    if cortex_responder is None:
        cortex_responder = cortex_enable_responder(conf=responder_conf)
    else:
        cortex_responder = cortex_update_responder_conf(conf=responder_conf, responder_id=cortex_responder.get("id"))

    # Create a case to trigger the responder
    case = thehive_create_case(domain_name=domain_name)

    # Check if the responder can be run on the case
    # Retrieve the responder_id to run the responder
    responders = thehive_list_case_responders(case_id=case.get("_id"))
    responder = None
    for r in responders:
        if r.get("name") == responder_name and r.get("id") == cortex_responder.get("id"):
            responder = r

    if responder is not None:
        # Trigger the responder
        response = requests.post(
            url=f"{theHive_fqdn}/api/connector/cortex/action",
            headers=theHive_headers,
            json={"responderId": responder.get("id"), "objectId": case.get("_id"), "objectType": case.get("_type")},
        )
        if response.status_code != 200:
            LOGGER.error(f"Error: Cannot run '{responder_name}' responder : {response.status_code}. {response.text}")
        LOGGER.info(f"Script execution is a success with the following parameters: domain '{domain_name}' and minutes '{minutes}'")
    else:
        LOGGER.error(f"Responder '{responder_name}' not found")
        thehive_delete_case(case.get("_id"))


if __name__ == "__main__":
    run_responder()
