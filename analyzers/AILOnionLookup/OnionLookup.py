#!/usr/bin/env python3
# encoding: utf-8

import re
import requests
from urllib.parse import urlparse
from cortexutils.analyzer import Analyzer

ONION_RE = re.compile(r'^[a-z2-7]{16,56}\.onion$', re.IGNORECASE)

class AILOnionLookup(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.base_url = self.get_param("config.base_url", "https://onion.ail-project.org")
        self.timeout  = int(self.get_param("config.timeout", 30))
        self.verify_tls = bool(self.get_param("config.verify_tls", True))
        self.csam_tag = 'dark-web:topic="pornography-child-exploitation"'

    def _extract_onion_host(self, value: str) -> str:
        v = (value or "").strip()
        # If it's a URL, parse hostname
        if re.match(r'^[a-z]+://', v, re.IGNORECASE):
            host = urlparse(v).hostname or ""
        else:
            host = v
        host = host.lower().strip()
        # strip optional port
        if ":" in host:
            host = host.split(":", 1)[0]
        # basic sanity
        if not host.endswith(".onion"):
            raise ValueError("Not a .onion host")
        if not ONION_RE.match(host):
            pass
        return host

    def run(self):
        try:
            onion = self._extract_onion_host(self.get_data())
            url = f"{self.base_url.rstrip('/')}/api/lookup/{onion}"
            r = requests.get(url, timeout=3, verify=self.verify_tls)
            
            if r.status_code == 200:
                resp = r.json()
                # API returns [{"error": "Invalid Domain"}, 404] for non-existent onions
                if isinstance(resp, list) and len(resp) == 2 and isinstance(resp[0], dict) and "error" in resp[0]:
                    self.error("Onion service not found")
                else:
                    # For csam tag testing
                    if isinstance(resp, dict) and "tags" in resp and isinstance(resp["tags"], list):
                        resp["tags"].append(self.csam_tag)
                    self.report(resp)
            else:
                self.error("API request failed")
                
        except Exception:
            self.error("Failed to process onion lookup")

    def operations(self, raw):
        ops = []
        try:
            # Skip operations if raw is an error array
            if isinstance(raw, list):
                return []
                
            tags = set()
            if isinstance(raw, dict) and "tags" in raw and isinstance(raw["tags"], list):
                tags.update(str(t) for t in raw["tags"])
            tags.update({"source:ail-onion-lookup", "scope:tor"})
            
            for t in sorted(tags):
                ops.append(self.build_operation("AddTagToArtifact", tag=t))

            if self.csam_tag in tags:
                ops.append(self.build_operation("AddTagToArtifact", tag="risk:csam-linked"))
                ops.append(self.build_operation("AddTagToCase", tag="risk:csam-linked"))
                task_title = "Review CSAM-linked onion"
                task_desc = (
                    "- Validate evidence handling (no download / safe preview)\n"
                    "- Update blocklists / mail/ web proxies as applicable\n"
                    "- Check prior sightings / related artifacts\n"
                    "- Consider legal/notification procedures per policy\n"
                    f"- Source: {self.base_url}\n"
                )
                ops.append(self.build_operation("CreateTask", title=task_title, description=task_desc))

        except Exception:
            return []
        return ops

    def artifacts(self, raw):
        artifacts = []
        return artifacts
    
    def summary(self, raw):
        taxonomies = []
        namespace = "OnionLookup"

        try:
            # Skip summary if raw is an error array
            if isinstance(raw, list):
                return {"taxonomies": []}

            tags = set()
            if isinstance(raw, dict) and "tags" in raw and isinstance(raw["tags"], list):
                tags.update(str(t) for t in raw["tags"])

            found = False
            if isinstance(raw, dict):
                found = any(raw.get(k) for k in ("id", "first_seen", "last_seen", "titles", "languages", "tags"))
                
            taxonomies.append(
                self.build_taxonomy("info", namespace, "Status", "found" if found else "not-found")
            )

            if self.csam_tag in tags:
                taxonomies.append(self.build_taxonomy("malicious", namespace, "CSAM", "linked"))

        except Exception:
            pass

        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    AILOnionLookup().run()