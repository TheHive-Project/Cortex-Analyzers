#!/usr/bin/env python3
"""DFIR Platform Phishing Analysis Analyzer for Cortex."""

import requests
from cortexutils.analyzer import Analyzer


class DFIRPlatformPhishingAnalysis(Analyzer):
    """Analyze phishing emails via the DFIR Platform API."""

    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param(
            "config.api_key", None, "Missing DFIR Platform API key"
        )
        self.base_url = self.get_param(
            "config.base_url", "https://api.dfir-lab.ch/v1"
        ).rstrip("/")

    def run(self):
        if self.data_type != "file":
            self.error("This analyzer only accepts file (EML) inputs.")
            return

        filepath = self.get_param("file", None, "No file provided")
        filename = self.get_param("filename", "email.eml")

        if not filename.lower().endswith(".eml"):
            self.error(
                "This analyzer expects EML files. "
                "Please submit a .eml email file."
            )
            return

        try:
            with open(filepath, "rb") as f:
                response = requests.post(
                    f"{self.base_url}/phishing/analyze",
                    headers={"X-API-Key": self.api_key},
                    files={"file": (filename, f, "message/rfc822")},
                    timeout=180,
                )
        except FileNotFoundError:
            self.error(f"File not found: {filepath}")
            return
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
        predicate = "Phishing"

        verdict = raw.get("verdict", "unknown").lower()
        confidence = raw.get("confidence", 0)

        if verdict == "phishing":
            level = "malicious"
            value = f"phishing ({confidence}% confidence)"
        elif verdict == "suspicious":
            level = "suspicious"
            value = f"suspicious ({confidence}% confidence)"
        elif verdict == "legitimate":
            level = "safe"
            value = "legitimate"
        else:
            level = "info"
            value = "unknown"

        taxonomies.append(
            self.build_taxonomy(level, namespace, predicate, value)
        )

        modules_triggered = raw.get("modules_triggered", 0)
        total_modules = raw.get("total_modules", 0)
        if total_modules > 0:
            taxonomies.append(
                self.build_taxonomy(
                    "info",
                    namespace,
                    "Modules",
                    f"{modules_triggered}/{total_modules}",
                )
            )

        auth = raw.get("authentication", {})
        spf = auth.get("spf", "unknown")
        dkim = auth.get("dkim", "unknown")
        dmarc = auth.get("dmarc", "unknown")

        auth_fails = sum(
            1 for r in [spf, dkim, dmarc] if r.lower() == "fail"
        )
        if auth_fails > 0:
            taxonomies.append(
                self.build_taxonomy(
                    "suspicious",
                    namespace,
                    "AuthFails",
                    f"{auth_fails}/3",
                )
            )

        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    DFIRPlatformPhishingAnalysis().run()
