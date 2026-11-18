#!/usr/bin/env python3
"""DECTRAX Cortex Analyzer for TheHive & Cortex SIRP.

Evaluates IP, domain, and FQDN observables against DECTRAX honeypots, canary tokens,
and line-rate firewall External Dynamic List (EDL) blocklists.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import requests
from requests.exceptions import RequestException

try:
    from cortexutils.analyzer import Analyzer
except ImportError:
    class Analyzer:
        """Fallback base Analyzer class for local testing outside Cortex container."""
        def __init__(self, job: Optional[Dict] = None):
            self.job = job or {}
            self.data_type = self.job.get("dataType", "ip")
            self.data = self.job.get("data", "")
            self.custom_fields = self.job.get("config", {})

        def get_param(self, name: str, default: Any = None, message: Optional[str] = None) -> Any:
            val = self.custom_fields.get(name, default)
            if val is None and message:
                raise ValueError(message)
            return val

        def get_data(self) -> str:
            return self.data

        def build_taxonomy(self, level: str, namespace: str, predicate: str, value: Any) -> Dict[str, str]:
            return {
                "level": level,
                "namespace": namespace,
                "predicate": predicate,
                "value": str(value)
            }

        def report(self, data: Dict[str, Any]):
            summary_data = self.summary(data)
            output = {"report": data, "summary": summary_data}
            return output

        def error(self, message: str):
            raise Exception(message)

        def summary(self, raw: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
            return {"taxonomies": []}


class DECTRAXAnalyzer(Analyzer):
    """Cortex Analyzer querying DECTRAX deception engine and firewall EDL feeds."""

    def __init__(self):
        super().__init__()
        self.url = self.get_param("config.url", "https://api.dectrax.com").rstrip("/")
        self.key = self.get_param("config.key", None)
        self.cert_check = self.get_param("config.cert_check", True)

        self.session = requests.Session()
        self.session.verify = self.cert_check
        self.session.headers.update({
            "User-Agent": "DECTRAX-Cortex-Analyzer/1.0",
            "Accept": "application/json, text/plain"
        })
        if self.key:
            self.session.headers["Authorization"] = f"Bearer {self.key}"

    def check_edl_blocklist(self, target_ip: str) -> bool:
        """Query /api/v1/edl/firewall.txt to check if target IP is in the active EDL."""
        try:
            res = self.session.get(f"{self.url}/api/v1/edl/firewall.txt", timeout=15)
            if res.status_code == 200:
                for line in res.text.splitlines():
                    cleaned = line.strip()
                    if cleaned and not cleaned.startswith("#") and cleaned == target_ip:
                        return True
        except RequestException:
            pass
        return False

    def query_threat_intel(self, observable: str) -> Dict[str, Any]:
        """Query DECTRAX intelligence API for decoy interaction logs."""
        try:
            res = self.session.get(f"{self.url}/api/v1/threats/intel/{observable}", timeout=15)
            if res.status_code == 200:
                return res.json()
        except RequestException:
            pass
        return {}

    def summary(self, raw: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
        """Generate normalized Cortex taxonomy tags."""
        taxonomies = []
        namespace = "DECTRAX"

        if raw.get("blocked"):
            taxonomies.append(self.build_taxonomy("malicious", namespace, "Interdiction", "Blocked in Firewall EDL"))
        elif raw.get("interactions", 0) > 0:
            count = raw.get("interactions", 0)
            taxonomies.append(self.build_taxonomy("suspicious", namespace, "Deception", f"{count} Decoy Interactions"))
        else:
            taxonomies.append(self.build_taxonomy("safe", namespace, "Status", "Clean"))

        return {"taxonomies": taxonomies}

    def run(self):
        """Execute analyzer routine on observable."""
        observable = self.get_data()
        data_type = self.data_type

        is_blocked = False
        if data_type == "ip":
            is_blocked = self.check_edl_blocklist(observable)

        intel = self.query_threat_intel(observable)
        interactions = intel.get("interactions", 1 if is_blocked else 0)
        decoy_types = intel.get("decoy_types", ["ssh-honeypot"] if is_blocked else [])

        raw_report = {
            "observable": observable,
            "dataType": data_type,
            "blocked": is_blocked,
            "interactions": interactions,
            "decoy_types": decoy_types,
            "intel": intel,
            "queried_at": datetime.now(timezone.utc).isoformat(),
            "source": "DECTRAX Autonomous Deception & Line-Rate Interdiction"
        }

        self.report(raw_report)


if __name__ == "__main__":
    DECTRAXAnalyzer().run()
