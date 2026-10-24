#!/usr/bin/env python3
"""DFIR Platform Exposure Scan Analyzer for Cortex."""

import requests
from cortexutils.analyzer import Analyzer


class DFIRPlatformExposureScan(Analyzer):
    """Scan a domain's attack surface via the DFIR Platform API."""

    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param(
            "config.api_key", None, "Missing DFIR Platform API key"
        )
        self.base_url = self.get_param(
            "config.base_url", "https://api.dfir-lab.ch/v1"
        ).rstrip("/")

    def run(self):
        if self.data_type != "domain":
            self.error("This analyzer only accepts domain observables.")
            return

        domain = self.get_data()

        try:
            response = requests.post(
                f"{self.base_url}/exposure/scan",
                headers={
                    "X-API-Key": self.api_key,
                    "Content-Type": "application/json",
                },
                json={"domain": domain},
                timeout=180,
            )
        except requests.exceptions.RequestException as e:
            self.error(f"Connection error: {str(e)}")
            return

        if response.status_code == 401:
            self.error("Invalid API key. Check your DFIR Platform API key.")
            return
        elif response.status_code == 402:
            self.error(
                "Insufficient credits. Top up at https://platform.dfir-lab.ch"
            )
            return
        elif response.status_code == 429:
            self.error("Rate limit exceeded. Please wait before retrying.")
            return
        elif response.status_code != 200:
            self.error(
                f"API error (HTTP {response.status_code}): {response.text}"
            )
            return

        try:
            self.report(response.json())
        except ValueError:
            self.error(f"Invalid JSON in API response: {response.text[:200]}")

    def summary(self, raw):
        taxonomies = []
        namespace = "DFIRPlatform"
        predicate = "Exposure"

        open_ports = raw.get("open_ports", [])
        port_count = len(open_ports) if isinstance(open_ports, list) else 0

        vulnerabilities = raw.get("vulnerabilities", [])
        vuln_count = (
            len(vulnerabilities) if isinstance(vulnerabilities, list) else 0
        )

        if vuln_count > 0:
            level = "malicious"
        elif port_count > 10:
            level = "suspicious"
        else:
            level = "info"

        taxonomies.append(
            self.build_taxonomy(
                level, namespace, "OpenPorts", str(port_count)
            )
        )

        if vuln_count > 0:
            taxonomies.append(
                self.build_taxonomy(
                    "malicious", namespace, "Vulnerabilities", str(vuln_count)
                )
            )

        ssl_grade = raw.get("ssl_grade")
        if ssl_grade:
            if ssl_grade in ("A+", "A"):
                ssl_level = "safe"
            elif ssl_grade in ("B", "C"):
                ssl_level = "suspicious"
            else:
                ssl_level = "malicious"
            taxonomies.append(
                self.build_taxonomy(
                    ssl_level, namespace, "SSLGrade", ssl_grade
                )
            )

        providers_count = raw.get("providers_queried", 0)
        if providers_count > 0:
            taxonomies.append(
                self.build_taxonomy(
                    "info", namespace, "Providers", str(providers_count)
                )
            )

        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    DFIRPlatformExposureScan().run()
