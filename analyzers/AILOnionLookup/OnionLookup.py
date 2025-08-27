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
            data_type = self.data_type
            data = self.get_data()
            onion = self._extract_onion_host(data)
            
            url = f"{self.base_url.rstrip('/')}/api/lookup/{onion}"
            r = requests.get(url, timeout=self.timeout, verify=self.verify_tls)            
            resp = r.json()
            
            # Normalize result
            tags = set()
            if isinstance(resp, dict):
                for k in ("tags",):
                    if k in resp and isinstance(resp[k], list):
                        tags.update(str(t) for t in resp[k])
            tags.update({"source:ail-onion-lookup", "scope:tor"})

            hit = (self.csam_tag in tags)

            summary = {
                "onion": onion,
                "hit": bool(hit),
                "indicator_type": data_type,
                "api_base": self.base_url,
                "observed_tags": sorted(tags),
                "raw": resp
            }

            self.report(summary)

        except Exception as e:
            self.error(f"Unhandled exception: {e}")

    def operations(self, raw):
        ops = []
        try:
            tags = set(raw.get("observed_tags", []) or [])
            for t in sorted(tags):
                ops.append(self.build_operation("AddTagToArtifact", tag=t))

            # If CSAM-linked, add case-level signal & a review task
            if raw.get("hit"):
                ops.append(self.build_operation("AddTagToArtifact", tag="risk:csam-linked"))
                ops.append(self.build_operation("AddTagToCase", tag="risk:csam-linked"))
                task_title = "Review CSAM-linked onion"
                task_desc = (
                    "- Validate evidence handling (no download / safe preview)\n"
                    "- Update blocklists / mail/ web proxies as applicable\n"
                    "- Check prior sightings / related artifacts\n"
                    "- Consider legal/notification procedures per policy\n"
                    f"- Source: {raw.get('api_base')}\n"
                    f"- Onion: {raw.get('onion')}\n"
                )
                ops.append(self.build_operation("CreateTask", title=task_title, description=task_desc))
            else:
                pass

        except Exception:
            # fail-safe
            return []
        return ops

    def artifacts(self, raw):
        artifacts = []
        return artifacts
    
    def summary(self, raw):
        taxonomies = []
        namespace = "OnionLookup"

        report = raw or {}
        resp = report.get("raw") or {}
        tags = set(report.get("observed_tags", []) or [])

        # Found vs not found
        found = isinstance(resp, dict) and any(resp.get(k) for k in ("id", "first_seen", "last_seen", "titles", "languages", "tags"))
        taxonomies.append(
            self.build_taxonomy("info", namespace, "Status", "found" if found else "not-found")
        )

        # CSAM-linked
        csam = self.csam_tag in tags or any("csam" in str(t).lower() for t in tags)
        if csam:
            taxonomies.append(self.build_taxonomy("malicious", namespace, "CSAM", "linked"))
        #else:
        #    taxonomies.append(self.build_taxonomy("safe", namespace, "CSAM", "not-linked"))

        return {"taxonomies": taxonomies}
  

if __name__ == "__main__":
    AILOnionLookup().run()