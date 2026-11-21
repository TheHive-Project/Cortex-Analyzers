#!/usr/bin/env python3
import ipaddress

import requests
from cortexutils.analyzer import Analyzer

API_URL = "https://api.vpndetection.io/"
TIMEOUT = 10
USER_AGENT = "cortex-analyzers-vpndetection/1.0"

# Detections in the order the report shows them. The first three are answered without a key.
DETECTIONS = (
    ("vpn", "VPN", "suspicious"),
    ("relay", "Relay", "suspicious"),
    ("tor", "Tor", "suspicious"),
    ("resproxy", "ResidentialProxy", "suspicious"),
    ("dcproxy", "DatacenterProxy", "suspicious"),
    ("mobproxy", "MobileProxy", "suspicious"),
    ("pubproxy", "PublicProxy", "suspicious"),
    ("hosting", "Hosting", "info"),
    ("cdn", "CDN", "info"),
    ("bot", "Bot", "info"),
)
# Without a key, once a free key's daily trial is spent, or past the organization's overage cap, these flags are
# absent or null, which must not read as a clean address.
KEYED_FLAGS = ("hosting", "cdn", "resproxy", "dcproxy", "mobproxy", "pubproxy")


class VPNDetectionAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.key = (self.get_param("config.key", None) or "").strip()

    def lookup(self, ip):
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"  # never in the URL, where it would end up in logs
        try:
            response = requests.get(API_URL + ip, headers=headers, timeout=TIMEOUT)
        except requests.RequestException as e:
            self.error(f"Could not reach the VPNDetection API: {e}")
        try:
            data = response.json()
        except ValueError:
            data = None
        if response.status_code != 200:
            message = data.get("error") if isinstance(data, dict) else None
            self.error(f"VPNDetection API error {response.status_code}: {message or response.reason}")
        if not isinstance(data, dict):
            self.error("The VPNDetection API returned a response that is not a JSON object.")
        return data

    def summary(self, raw):
        taxonomies = []
        for flag, predicate, level in DETECTIONS:
            if raw.get(f"is_{flag}") is not True:
                continue
            detail = raw.get(flag) if isinstance(raw.get(flag), dict) else {}
            value = detail.get("provider_name") or detail.get("provider") or "True"
            taxonomies.append(self.build_taxonomy(level, "VPNDetection", predicate, value))
        if not taxonomies:
            value = "None (partial)" if raw.get("partial") else "None"
            taxonomies.append(self.build_taxonomy("info", "VPNDetection", "Detection", value))
        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)
        if self.data_type != "ip":
            self.notSupported()
        value = self.get_data().strip()
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            self.error(f"{value} is not a valid IP address.")
        if not ip.is_global:
            self.error(f"{ip} is a private or reserved address and cannot be looked up.")
        data = self.lookup(str(ip))
        if data.get("is_bogon"):
            self.error(f"VPNDetection reports {ip} as a bogon: a private or reserved address.")
        data["partial"] = any(data.get(f"is_{flag}") is None for flag in KEYED_FLAGS)
        self.report(data)


if __name__ == "__main__":
    VPNDetectionAnalyzer().run()
