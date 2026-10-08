#!/usr/bin/env python3
"""DFIR Platform IOC Enrichment Analyzer for Cortex."""

import requests
from cortexutils.analyzer import Analyzer


class DFIRPlatformIOCEnrichment(Analyzer):
    """Enrich IOCs (IPs, domains, hashes, URLs) via the DFIR Platform API."""

    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param(
            "config.api_key", None, "Missing DFIR Platform API key"
        )
        self.base_url = self.get_param(
            "config.base_url", "https://api.dfir-lab.ch/v1"
        ).rstrip("/")

    def run(self):
        data_type = self.data_type
        if data_type not in ("ip", "domain", "hash", "url"):
            self.error(f"Unsupported data type: {data_type}")
            return

        observable = self.get_data()

        try:
            response = requests.post(
                f"{self.base_url}/ioc/enrich",
                headers={
                    "X-API-Key": self.api_key,
                    "Content-Type": "application/json",
                },
                json={"type": data_type, "value": observable},
                timeout=120,
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
        level = "info"
        namespace = "DFIRPlatform"
        predicate = "IOCEnrichment"

        malicious_count = raw.get("malicious_count", 0)
        total_sources = raw.get("total_sources", 0)

        if malicious_count > 0:
            level = "malicious"
            value = f"{malicious_count}/{total_sources} malicious"
        elif raw.get("suspicious", False):
            level = "suspicious"
            value = f"suspicious ({total_sources} sources)"
        else:
            level = "safe"
            value = f"clean ({total_sources} sources)"

        taxonomies.append(
            self.build_taxonomy(level, namespace, predicate, value)
        )

        risk_score = raw.get("risk_score")
        if risk_score is not None:
            if risk_score >= 80:
                score_level = "malicious"
            elif risk_score >= 40:
                score_level = "suspicious"
            else:
                score_level = "safe"
            taxonomies.append(
                self.build_taxonomy(
                    score_level, namespace, "RiskScore", f"{risk_score}/100"
                )
            )

        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    DFIRPlatformIOCEnrichment().run()
