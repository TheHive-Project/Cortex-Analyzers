#!/usr/bin/env python3
"""
isMalicious Cortex Analyzer

Checks if an IP address or domain is malicious using isMalicious.com threat intelligence.
"""

import requests
from cortexutils.analyzer import Analyzer


class IsMaliciousAnalyzer(Analyzer):
    """Cortex analyzer for isMalicious threat intelligence."""

    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param("config.api_key", None, "Missing isMalicious API key")
        self.api_url = self.get_param("config.api_url", "https://ismalicious.com").rstrip("/")

    def run(self):
        try:
            data = self.get_data()

            if self.data_type not in ["ip", "domain", "fqdn"]:
                self.notSupported()
                return

            response = requests.get(
                f"{self.api_url}/api/check",
                params={"query": data, "enrichment": "standard"},
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Accept": "application/json",
                },
                timeout=30,
            )

            if response.status_code == 401:
                self.error("Invalid API key")
                return

            if response.status_code == 429:
                self.error("Rate limit exceeded")
                return

            response.raise_for_status()
            result = response.json()

            self.report({
                "malicious": result.get("malicious", False),
                "riskScore": result.get("riskScore", {}).get("score"),
                "confidence": result.get("confidence", {}).get("score"),
                "classification": result.get("classification", {}),
                "categories": result.get("categories", []),
                "sources": result.get("sources", []),
                "reputation": result.get("reputation", {}),
                "geo": result.get("geo", {}),
                "whois": result.get("whois", {}),
            })

        except requests.exceptions.Timeout:
            self.error("Request timed out")
        except requests.exceptions.RequestException as e:
            self.error(f"API request failed: {str(e)}")
        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        taxonomies = []

        # Malicious status
        is_malicious = raw.get("malicious", False)
        level = "malicious" if is_malicious else "safe"
        taxonomies.append(
            self.build_taxonomy(level, "isMalicious", "Status", "Malicious" if is_malicious else "Clean")
        )

        # Risk score
        risk_score = raw.get("riskScore")
        if risk_score is not None:
            if risk_score >= 80:
                score_level = "malicious"
            elif risk_score >= 50:
                score_level = "suspicious"
            else:
                score_level = "safe"
            taxonomies.append(
                self.build_taxonomy(score_level, "isMalicious", "Risk Score", risk_score)
            )

        # Threat classification
        classification = raw.get("classification", {})
        primary = classification.get("primary")
        if primary:
            taxonomies.append(
                self.build_taxonomy("info", "isMalicious", "Category", primary)
            )

        # Detection sources count
        sources = raw.get("sources", [])
        if sources:
            taxonomies.append(
                self.build_taxonomy(
                    "malicious" if is_malicious else "info",
                    "isMalicious",
                    "Sources",
                    len(sources)
                )
            )

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []

        # Extract country as artifact
        geo = raw.get("geo", {})
        country = geo.get("country") or geo.get("countryCode")
        if country:
            artifacts.append(self.build_artifact("other", country, tags=["country", "isMalicious"]))

        # Extract ASN if available
        whois = raw.get("whois", {})
        asn = whois.get("asn", {})
        if asn.get("asn"):
            artifacts.append(self.build_artifact("other", f"AS{asn['asn']}", tags=["asn", "isMalicious"]))

        return artifacts


if __name__ == "__main__":
    IsMaliciousAnalyzer().run()
