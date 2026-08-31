#!/usr/bin/env python3
# encoding: utf-8

import requests
from cortexutils.analyzer import Analyzer


class ThreatFoxAnalyzer(Analyzer):
    BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param(
            "config.key", None, "Missing ThreatFox API key (Auth-Key)"
        )

    def _query(self, payload):
        headers = {
            "Auth-Key": self.api_key,
            "Content-Type": "application/json",
        }
        try:
            response = requests.post(self.BASE_URL, json=payload, headers=headers, timeout=30)
        except requests.exceptions.RequestException as e:
            self.error("Unable to reach ThreatFox: {}".format(e))

        if response.status_code in (401, 403):
            self.error(
                "ThreatFox rejected the Auth-Key (HTTP {}): {}".format(
                    response.status_code, response.text.strip()
                )
            )
        elif not response.ok:
            self.error("ThreatFox returned HTTP {}".format(response.status_code))

        try:
            data = response.json()
        except ValueError as e:
            self.error("Unable to parse ThreatFox response: {}".format(e))

        if "error" in data:
            self.error("ThreatFox error: {}".format(data["error"]))

        return data

    def run(self):
        observable = self.get_data()

        if self.data_type == "hash":
            payload = {"query": "search_hash", "hash": observable}
        elif self.data_type in ("ip", "domain", "fqdn", "url"):
            payload = {"query": "search_ioc", "search_term": observable, "exact_match": False}
        else:
            self.notSupported()
            return

        response = self._query(payload)
        query_status = response.get("query_status")
        iocs = response.get("data") or [] if query_status == "ok" else []

        self.report({
            "observable": observable,
            "query_status": query_status,
            "iocs": iocs,
        })

    def summary(self, raw):
        taxonomies = []
        iocs = raw.get("iocs", [])

        if not iocs:
            taxonomies.append(self.build_taxonomy("safe", "ThreatFox", "IOC", 0))
            return {"taxonomies": taxonomies}

        taxonomies.append(self.build_taxonomy("malicious", "ThreatFox", "IOC", len(iocs)))

        malware_families = sorted({
            ioc.get("malware_printable") for ioc in iocs if ioc.get("malware_printable")
        })
        if malware_families:
            value = ", ".join(malware_families[:3])
            if len(malware_families) > 3:
                value += ", ..."
            taxonomies.append(self.build_taxonomy("malicious", "ThreatFox", "Malware", value))

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        seen = set()

        def add(data_type, value, malware=None):
            key = (data_type, value)
            if not value or key in seen:
                return
            seen.add(key)
            tags = ["ThreatFox"]
            if malware:
                tags.append(malware)
            artifacts.append(self.build_artifact(data_type, value, tags=tags))

        for ioc in raw.get("iocs", []):
            ioc_value = ioc.get("ioc")
            ioc_type = ioc.get("ioc_type") or ""
            malware = ioc.get("malware_printable")

            if ioc_type == "ip:port" and ioc_value:
                add("ip", ioc_value.split(":")[0], malware)
            elif ioc_type in ("domain",):
                add("domain", ioc_value, malware)
            elif ioc_type in ("url",):
                add("url", ioc_value, malware)
            elif ioc_type in ("md5_hash", "sha256_hash", "sha1_hash"):
                add("hash", ioc_value, malware)

            for sample in ioc.get("malware_samples") or []:
                add("hash", sample.get("md5_hash"), malware)
                add("hash", sample.get("sha256_hash"), malware)

        return artifacts


if __name__ == "__main__":
    ThreatFoxAnalyzer().run()
