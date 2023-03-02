#!/usr/bin/env python3
# encoding: utf-8
from ipaddress import ip_address

import requests
from cortexutils.analyzer import Analyzer
from requests import HTTPError


class IntelligenceCenterAnalyzer(Analyzer):

    TYPES_MAPPING = {
        "url": "url",
        "domain": "domain-name",
        "fqdn": "domain-name",
        "hash": "file",
        "ip": ["ipv4-addr", "ipv6-addr"],
    }

    DEFAULT_URL = "https://app.sekoia.io"

    @property
    def url(self):
        if self.service == "observables":
            return "{}/api/v2/inthreat/observables/search?with_indicated_threats=1".format(self.base_url)
        path = ""
        if self.service == "context":
            path = "/context"
        return "{}/api/v2/inthreat/indicators{}".format(self.base_url, path)

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param("config.service", None, "Service parameter is missing")
        self.api_key = self.get_param("config.api_key", None, "Missing Api Key")
        self.base_url = self.get_param("config.url", self.DEFAULT_URL)
        if not self.base_url:
            # Case of empty string
            self.base_url = self.DEFAULT_URL

    def run(self):
        payload = self.get_payload()
        results = self.perform_request(payload)
        self.report({"results": results})

    def summary(self, raw):
        count = len(raw.get("results", []))
        value = "{} result{}".format(count, "s" if count > 1 else "")

        taxonomies = []
        if count == 0:
            taxonomies.append(self.build_taxonomy("safe", "SEKOIA", self.service, value))
        elif self.service == "observables":
            has_threats = any(res.get("x_ic_indicated_threats") for res in raw["results"])
            if has_threats:
                taxonomies.append(self.build_taxonomy("malicious", "SEKOIA", self.service, value))
        else:
            taxonomies.append(self.build_taxonomy("malicious", "SEKOIA", self.service, value))

        return {"taxonomies": taxonomies}

    def get_payload(self):
        if self.service == "observables":
            return {"term": self.get_data()}
        return {"type": self.get_ic_type(), "value": self.get_data()}

    def get_ic_type(self):
        if self.data_type not in self.TYPES_MAPPING.keys():
            self.error("Invalid data type")
        if self.data_type != "ip":
            return self.TYPES_MAPPING[self.data_type]

        # Check what kind of IP it is.
        try:
            address = ip_address(self.get_data())
            return "ipv4-addr" if address.version == 4 else "ipv6-addr"
        except ValueError:
            self.error("Invalid IP address")

    def perform_request(self, payload):
        """
        Send the request to the API.

        The main error codes are handled here
        """
        try:
            return self._send_request(payload)
        except HTTPError as ex:
            if ex.response.status_code == 401:
                self.error("Unauthorized to query the API. Is the API key valid ?")
            if ex.response.status_code == 403:
                self.error(
                    "Forbidden to query the API. Does the API key has the right permissions ?"
                )
            if ex.response.status_code == 429:
                self.error("Quota exhausted.")
            self.error("API returned with the error code {}".format(str(ex.response.status_code)))

    def _send_request(self, payload):
        headers = {"Authorization": "Bearer {}".format(self.api_key)}
        if self.service == "observables":
            response = requests.post(self.url, json=payload, headers=headers)
        else: 
            response = requests.get(self.url, params=payload, headers=headers)
        response.raise_for_status()
        return response.json()["items"]


if __name__ == "__main__":
    IntelligenceCenterAnalyzer().run()
