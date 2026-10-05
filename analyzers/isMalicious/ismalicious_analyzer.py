#!/usr/bin/env python3
"""
isMalicious Cortex Analyzer

Checks if an IP address or domain is malicious using isMalicious.com threat intelligence.
"""

import requests
from cortexutils.analyzer import Analyzer

# Sent as the User-Agent so the API can tell this analyzer's calls apart. Deliberately not the
# `version` of the flavor JSON, which names the analyzer in Cortex and its report templates.
ANALYZER_VERSION = "1.0.1"
USER_AGENT = f"ismalicious-cortex/{ANALYZER_VERSION} (+https://ismalicious.com)"

# riskScore.level from the API (>=80 critical, >=60 high, >=40 medium, >=20 low, else safe;
# "inconclusive" when there is too little evidence for a verdict) mapped to taxonomy levels.
RISK_LEVEL_TO_TAXONOMY = {
    "critical": "malicious",
    "high": "malicious",
    "medium": "suspicious",
    "low": "safe",
    "safe": "safe",
    "inconclusive": "info",
}


def as_dict(value):
    """Response blocks may be null or, for raw upstream payloads (geo, whois), not objects."""
    return value if isinstance(value, dict) else {}


def is_threat_source(source):
    """A listing counts as a detection only when its threatClass is "threat" or absent.

    "infrastructure" (cloud and CDN ranges, Tor exits, DoH resolvers), "policy" (ads, tracking)
    and "allowlist" listings describe what the observable is, not that it did anything malicious.
    """
    if not isinstance(source, dict):
        return True
    return source.get("threatClass") in (None, "", "threat")


def score_to_taxonomy_level(risk_score, risk_level):
    level = RISK_LEVEL_TO_TAXONOMY.get(risk_level)
    if level is not None:
        return level
    # Reports stored before riskLevel was added: same thresholds as the API.
    if risk_score is None:
        return "info"
    if risk_score >= 60:
        return "malicious"
    if risk_score >= 40:
        return "suspicious"
    return "safe"


class IsMaliciousAnalyzer(Analyzer):
    """Cortex analyzer for isMalicious threat intelligence."""

    def __init__(self):
        Analyzer.__init__(self)
        # The X-API-KEY value from the isMalicious account page: Base64 of apiKey:apiSecret.
        self.api_key = self.get_param("config.api_key", None, "Missing isMalicious API key")
        self.api_url = (self.get_param("config.api_url", None) or "https://api.ismalicious.com").rstrip("/")

    def check_endpoint(self):
        """The API host serves /check; the web host (the former default api_url) serves /api/check."""
        if "//ismalicious.com" in self.api_url:
            return f"{self.api_url}/api/check"
        return f"{self.api_url}/check"

    def run(self):
        try:
            data = self.get_data()

            if self.data_type not in ["ip", "domain", "fqdn"]:
                self.notSupported()
                return

            # Redirects are not followed, so the credential is only ever sent to api_url.
            response = requests.get(
                self.check_endpoint(),
                params={"query": data, "enrichment": "standard"},
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
                timeout=30,
                allow_redirects=False,
            )

            if 300 <= response.status_code < 400:
                self.error(
                    f"isMalicious API answered with a redirect (HTTP {response.status_code}); "
                    "set api_url to https://api.ismalicious.com"
                )
                return

            if response.status_code == 401:
                self.error("Invalid API key")
                return

            if response.status_code == 429:
                self.error("Rate limit or quota exceeded")
                return

            response.raise_for_status()
            result = as_dict(response.json())

            # The check response has no top-level categories for IPs and domains: each listing
            # carries its own. Only threat listings count as detections.
            sources = result.get("sources") or []
            threat_sources = [source for source in sources if is_threat_source(source)]
            categories = []
            for source in threat_sources:
                if not isinstance(source, dict):
                    continue
                for value in [source.get("category")] + (source.get("categories") or []):
                    if value and value not in categories:
                        categories.append(value)

            risk = as_dict(result.get("riskScore"))
            self.report({
                "malicious": bool(result.get("malicious", False)),
                "riskScore": risk.get("score"),
                "riskLevel": risk.get("level"),
                "confidence": as_dict(result.get("confidence")).get("score"),
                "classification": as_dict(result.get("classification")),
                "categories": categories,
                "sources": threat_sources,
                "infrastructure": as_dict(result.get("infrastructure")),
                "reputation": as_dict(result.get("reputation")),
                "geo": as_dict(result.get("geo")),
                "whois": as_dict(result.get("whois")),
            })

        except requests.exceptions.Timeout:
            self.error("Request timed out")
        except requests.exceptions.RequestException as e:
            self.error(f"API request failed: {str(e)}")
        except ValueError:
            self.error("isMalicious API returned an invalid JSON response")
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

        # Risk score, with the level computed by the API
        risk_score = raw.get("riskScore")
        risk_level = raw.get("riskLevel")
        if risk_score is not None or risk_level:
            value = risk_score if risk_score is not None else risk_level
            if risk_score is not None and risk_level:
                value = f"{risk_score} ({risk_level})"
            taxonomies.append(
                self.build_taxonomy(
                    score_to_taxonomy_level(risk_score, risk_level), "isMalicious", "Risk Score", value
                )
            )

        # Threat classification
        primary = as_dict(raw.get("classification")).get("primary")
        if primary:
            taxonomies.append(
                self.build_taxonomy("info", "isMalicious", "Category", primary)
            )

        # Detection sources count: threat listings only (reports stored before this version kept
        # every listing under `sources`, so filter again)
        sources = [source for source in raw.get("sources") or [] if is_threat_source(source)]
        if sources:
            taxonomies.append(
                self.build_taxonomy(
                    "malicious" if is_malicious else "info",
                    "isMalicious",
                    "Sources",
                    len(sources)
                )
            )

        # What the observable is known as (cloud, cdn, tor-exit...), not a verdict
        attributes = as_dict(raw.get("infrastructure")).get("attributes")
        if attributes:
            taxonomies.append(
                self.build_taxonomy("info", "isMalicious", "Infrastructure", ", ".join(str(a) for a in attributes))
            )

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []

        # Extract country as artifact
        geo = as_dict(raw.get("geo"))
        country = geo.get("country") or geo.get("countryCode")
        if country:
            artifacts.append(self.build_artifact("other", country, tags=["country", "isMalicious"]))

        # Extract ASN if available
        asn = as_dict(as_dict(raw.get("whois")).get("asn"))
        if asn.get("asn"):
            artifacts.append(self.build_artifact("other", f"AS{asn['asn']}", tags=["asn", "isMalicious"]))

        return artifacts


if __name__ == "__main__":
    IsMaliciousAnalyzer().run()
