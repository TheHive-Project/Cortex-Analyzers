#!/usr/bin/env python3

import requests
from requests.exceptions import RequestException

from cortexutils.analyzer import Analyzer


class FlowtriqAnalyzer(Analyzer):
    """
    Flowtriq DDoS Intelligence Analyzer

    Queries the Flowtriq API to check whether an IP address has been
    observed as a source or target of DDoS attacks. Returns risk score,
    attack families, severity breakdown, peak traffic rates, and
    related attacker IPs.

    API docs: https://flowtriq.com/docs
    """

    _TIMEOUT = 15

    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param(
            "config.api_key", None, "Missing Flowtriq API key"
        )
        self.api_url = (
            self.get_param("config.api_url", "https://flowtriq.com")
            .strip()
            .rstrip("/")
        )
        self.proxies = {
            "https": self.get_param("config.proxy_https"),
            "http": self.get_param("config.proxy_http"),
        }

    def run(self):
        if self.data_type != "ip":
            self.notSupported()
            return

        ip = self.get_data()

        try:
            response = requests.post(
                f"{self.api_url}/api/ip-lookup.php",
                json={"ip": ip},
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "Cortex-Flowtriq/1.0",
                },
                proxies=self.proxies,
                timeout=self._TIMEOUT,
                verify=True,
            )
        except RequestException as e:
            self.error(f"Flowtriq API request failed: {e}")
            return

        if response.status_code == 401:
            self.error("Flowtriq API authentication failed. Check your API key.")
            return

        if response.status_code == 429:
            self.error("Flowtriq API rate limit exceeded. Try again later.")
            return

        if not (200 <= response.status_code < 300):
            self.error(
                f"Flowtriq API returned HTTP {response.status_code}: "
                f"{response.text[:200]}"
            )
            return

        try:
            data = response.json()
        except ValueError:
            self.error("Flowtriq API returned invalid JSON")
            return

        if not data.get("ok"):
            self.error(data.get("error", "Flowtriq API returned an error"))
            return

        result = self._build_result(ip, data)
        self.report(result)

    def _build_result(self, ip, data):
        """Structure the API response for the Cortex report."""
        risk_score = data.get("risk_score", 0)
        found = data.get("found", False)
        reputation = data.get("reputation") or {}
        incidents = data.get("incidents") or {}
        threat_intel = data.get("threat_intel") or []
        related_ips = data.get("related_ips") or {}
        ioc_matches = data.get("ioc_matches") or {}

        total_incidents = incidents.get("total", 0)
        families = incidents.get("attack_families") or {}
        severity = incidents.get("severity") or {}
        records = incidents.get("records") or []

        return {
            "ip": ip,
            "found": found,
            "risk_score": risk_score,
            "reputation": {
                "attack_count": reputation.get("attack_count", 0),
                "tenants_seen": reputation.get("tenants_seen", 0),
                "first_seen": reputation.get("first_seen"),
                "last_seen": reputation.get("last_seen"),
                "top_attack_family": reputation.get("top_attack_family"),
                "top_protocol": reputation.get("top_protocol"),
                "country": reputation.get("country"),
                "asn": reputation.get("asn"),
                "peak_pps": reputation.get("peak_pps", 0),
                "tags": reputation.get("tags") or [],
            },
            "incidents": {
                "total": total_incidents,
                "attack_families": families,
                "severity": severity,
                "records": records[:20],
            },
            "threat_intel": threat_intel,
            "related_ips": related_ips,
            "ioc_matches": ioc_matches,
        }

    def summary(self, raw):
        taxonomies = []

        if not raw or not raw.get("found"):
            taxonomies.append(
                self.build_taxonomy("safe", "Flowtriq", "Risk", "None")
            )
            return {"taxonomies": taxonomies}

        risk_score = raw.get("risk_score", 0)

        # Risk score taxonomy
        if risk_score >= 75:
            level = "malicious"
        elif risk_score >= 40:
            level = "suspicious"
        elif risk_score > 0:
            level = "info"
        else:
            level = "safe"

        taxonomies.append(
            self.build_taxonomy(level, "Flowtriq", "Risk", f"{risk_score}/100")
        )

        # Attack count
        reputation = raw.get("reputation") or {}
        attack_count = reputation.get("attack_count", 0)
        if attack_count > 0:
            atk_level = "malicious" if attack_count >= 10 else "suspicious"
            taxonomies.append(
                self.build_taxonomy(atk_level, "Flowtriq", "Attacks", attack_count)
            )

        # Primary attack family
        top_family = reputation.get("top_attack_family")
        if top_family:
            taxonomies.append(
                self.build_taxonomy("info", "Flowtriq", "Vector", top_family)
            )

        # Incident count
        total_incidents = (raw.get("incidents") or {}).get("total", 0)
        if total_incidents > 0:
            taxonomies.append(
                self.build_taxonomy("info", "Flowtriq", "Incidents", total_incidents)
            )

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []

        if not raw or not raw.get("found"):
            return artifacts

        # Related attacker IPs
        related_ips = raw.get("related_ips") or {}
        for related_ip in list(related_ips.keys())[:10]:
            artifacts.append(
                self.build_artifact("ip", related_ip, tags=["Flowtriq:related-attacker"])
            )

        return artifacts


if __name__ == "__main__":
    FlowtriqAnalyzer().run()
