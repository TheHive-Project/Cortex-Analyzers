#!/usr/bin/env python3
"""Cortex analyzer for macadress.com.

Takes a MAC address observable and returns the vendor identity, an inferred
device category, virtualization / container-network detection, special-use
address classification, and MAC-randomization confidence, using the
macadress.com API (the same lookup the JSON API, MCP server and website
run).
"""

import requests
from cortexutils.analyzer import Analyzer

API_URL = "https://api.macadress.com/v1/mac/"
USER_AGENT = "Cortex-Analyzer (macadress.com)"
TIMEOUT = 15


class MacadressAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param(
            "config.api_key", None, "Missing macadress.com API key (config.api_key)"
        )

    def run(self):
        if self.data_type not in ("mac", "other"):
            return self.notSupported()

        mac = (self.get_data() or "").strip()
        if not mac:
            return self.error("No MAC address supplied")

        try:
            resp = requests.get(
                API_URL + mac,
                headers={
                    "Authorization": "Bearer " + self.api_key,
                    "User-Agent": USER_AGENT,
                },
                timeout=TIMEOUT,
            )
        except requests.exceptions.RequestException as exc:
            return self.error("macadress.com API not reachable: %s" % exc)

        if resp.status_code == 400:
            return self.error("Not a valid MAC address: %s" % mac)
        if resp.status_code == 401:
            return self.error("macadress.com rejected the API key (HTTP 401)")
        if resp.status_code == 429:
            return self.error(
                "macadress.com rate limit or monthly quota exceeded (HTTP 429)"
            )
        if resp.status_code != 200:
            return self.error(
                "macadress.com API error (HTTP %d)" % resp.status_code
            )

        try:
            report = resp.json()
        except ValueError:
            return self.error("macadress.com returned a non-JSON response")

        self.report(report)

    def summary(self, raw):
        taxonomies = []
        ns = "macadress"

        if not raw.get("valid", False):
            taxonomies.append(self.build_taxonomy("info", ns, "MAC", "invalid"))
            return {"taxonomies": taxonomies}

        organization = raw.get("organization")
        if organization:
            taxonomies.append(
                self.build_taxonomy("info", ns, "Vendor", organization)
            )
        elif raw.get("locally_administered"):
            taxonomies.append(
                self.build_taxonomy("info", ns, "Vendor", "locally-administered")
            )
        else:
            taxonomies.append(
                self.build_taxonomy("info", ns, "Vendor", "unregistered")
            )

        category = (raw.get("device") or {}).get("category")
        if category and category != "unknown":
            taxonomies.append(self.build_taxonomy("info", ns, "Device", category))

        virtualization = raw.get("virtualization") or {}
        if virtualization.get("detected"):
            platform = virtualization.get("platform") or "virtual"
            taxonomies.append(
                self.build_taxonomy("info", ns, "Virtualization", platform)
            )

        special_use = raw.get("special_use") or {}
        if special_use.get("detected"):
            label = (
                special_use.get("name")
                or special_use.get("type")
                or "special-use"
            )
            taxonomies.append(self.build_taxonomy("info", ns, "SpecialUse", label))

        confidence = raw.get("randomization_confidence", "none")
        if raw.get("potentially_randomized") and confidence in ("possible", "likely"):
            level = "suspicious" if confidence == "likely" else "info"
            taxonomies.append(
                self.build_taxonomy(level, ns, "Randomized", confidence)
            )

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        seen = set()
        for path in (("vendor", "lookup_url"), ("local_vendor_derivation", "lookup_url")):
            node = raw
            for key in path:
                node = node.get(key) if isinstance(node, dict) else None
            if isinstance(node, str) and node and node not in seen:
                seen.add(node)
                artifacts.append(self.build_artifact("url", node))
        return artifacts


if __name__ == "__main__":
    MacadressAnalyzer().run()
