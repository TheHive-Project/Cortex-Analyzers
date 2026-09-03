#!/usr/bin/env python3
"""HashScanner Cortex analyzer — look up a file hash in the NIST NSRL.

A match means the file is *known* (cataloged in NSRL), which lets analysts filter out
files they already recognise — it is NOT a safe, clean, or malicious verdict.

Get a free API key at https://www.hashscanner.com/register
"""

import requests
from cortexutils.analyzer import Analyzer

API_DEFAULT = "https://api.hashscanner.com/v1"


class HashScannerAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param(
            "config.api_key", None, "HashScanner API key is missing"
        )
        self.api_url = self.get_param("config.api_url", API_DEFAULT).rstrip("/")
        self.timeout = self.get_param("config.timeout", 30)

    def summary(self, raw):
        # "known" / "unknown" are stated as info — NSRL membership is not a verdict.
        value = "Known" if raw.get("found") else "Unknown"
        return {"taxonomies": [self.build_taxonomy("info", "HashScanner", "NSRL", value)]}

    def run(self):
        if self.data_type != "hash":
            self.error("HashScanner only supports the 'hash' data type")
        observable = self.get_data() or ""
        h = observable.strip().lower()
        if not h:
            self.error("No hash supplied")

        headers = {
            "Authorization": "Bearer {}".format(self.api_key),
            "User-Agent": "hashscanner-cortex/1.0",
        }
        try:
            resp = requests.get(
                "{}/hash/{}".format(self.api_url, h),
                headers=headers,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            self.error("HashScanner request failed: {}".format(exc))

        if resp.status_code == 200:
            self.report(resp.json())
            return
        if resp.status_code == 404:
            # Not cataloged in NSRL — a valid "unknown" result, not an error.
            self.report({"found": False, "hash": h})
            return
        if resp.status_code == 401:
            self.error("Invalid HashScanner API key")
        if resp.status_code == 403:
            self.error("HashScanner subscription inactive — renew or upgrade")
        if resp.status_code == 429:
            self.error("HashScanner rate limit or monthly quota exceeded")
        self.error("HashScanner error {}: {}".format(resp.status_code, resp.text))


if __name__ == "__main__":
    HashScannerAnalyzer().run()
