#!/usr/bin/env python3
# encoding: utf-8

import json
import os
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
        self.csam_tag = 'dark-web:topic="child-sexual-abuse-material"'
        self.tag_descriptions = self._load_tag_descriptions()

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
            raise ValueError(f"Invalid .onion domain format: {host}")
        return host

    def _load_tag_descriptions(self):
        """Load tag descriptions from machinetag.json"""
        machinetag_path = os.path.join(os.path.dirname(__file__), 'machinetag.json')
        if not os.path.exists(machinetag_path):
            # Log warning but continue without tag descriptions
            return {}
            
        try:
            with open(machinetag_path, 'r', encoding='utf-8') as f:
                self.machinetag_data = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            # Log warning and continue without tag descriptions
            return {}
        
        descriptions = {}
        try:
            for value_info in self.machinetag_data['values']:
                predicate = value_info['predicate']
                for entry in value_info['entry']:
                    key = f"dark-web:{predicate}={entry['value']}"
                    descriptions[key] = {
                        'description': entry['description'],
                        'expanded': entry['expanded'],
                        'value': entry['value']
                    }
        except (KeyError, TypeError) as e:
            # Return empty dict if machinetag structure is unexpected
            return {}
        
        return descriptions

    def _count_detections(self, tags):
        """Count total detections and malicious detections"""
        if not tags or not isinstance(tags, list):
            return {'total': 0, 'malicious': 0}
            
        sanitized_tags = self._create_sanitized_tags(tags)
        
        total_detections = len(tags)
        malicious_detections = 0
        
        for tag in sanitized_tags:
            if tag in self.tag_descriptions:
                # ANY tag matching an entry in machinetag.json is considered malicious / notables
                malicious_detections += 1
        
        return {'total': total_detections, 'malicious': malicious_detections}

    def _create_sanitized_tags(self, tags):
        """Create sanitized tags by stripping all quotes, escapes, and whitespace"""
        return [re.sub(r'["\\\s]', '', tag.strip()) for tag in tags]

    def _enrich_tags(self, tags):
        """Add human-readable descriptions to tags for security analysts"""
        enriched = []
        sanitized = self._create_sanitized_tags(tags)
        
        for original, clean in zip(tags, sanitized):
            tag_info = {
                'original': original,
                'sanitized': clean,
                'description': None,
                'expanded': None
            }
            
            if clean in self.tag_descriptions:
                tag_info.update(self.tag_descriptions[clean])
            
            enriched.append(tag_info)
        
        return enriched

    def run(self):
        try:
            # Extract and validate onion host
            try:
                onion = self._extract_onion_host(self.get_data())
            except ValueError as e:
                self.error(f"Invalid onion domain: {str(e)}")
                return
            except Exception as e:
                self.error(f"Error processing input data: {str(e)}")
                return
            
            # Build API URL
            url = f"{self.base_url.rstrip('/')}/api/lookup/{onion}"
            
            # Make API request
            try:
                r = requests.get(url, timeout=self.timeout, verify=self.verify_tls)
            except requests.exceptions.ConnectTimeout:
                self.error(f"Connection timeout to {self.base_url}")
                return
            except requests.exceptions.ConnectionError:
                self.error(f"Connection failed to {self.base_url}")
                return
            except requests.exceptions.RequestException as e:
                self.error(f"Request failed: {str(e)}")
                return
            
            if r.status_code == 200:
                try:
                    resp = r.json()
                except ValueError as e:
                    self.error(f"Invalid JSON response: {str(e)}")
                    return
                    
                # API returns [{"error": "Invalid Domain"}, 404] for non-existent onions
                if isinstance(resp, list) and len(resp) == 2 and isinstance(resp[0], dict) and "error" in resp[0]:
                    self.error("Onion service not found")
                else:
                    # For csam tag testing
                    # if isinstance(resp, dict) and "tags" in resp and isinstance(resp["tags"], list):
                    #     resp["tags"].append(self.csam_tag)
                    # Add enriched tags with analyst-friendly descriptions
                    if isinstance(resp, dict) and "tags" in resp and isinstance(resp["tags"], list):
                        try:
                            resp["tags_enriched"] = self._enrich_tags(resp["tags"])
                            resp["tags_sanitized"] = self._create_sanitized_tags(resp["tags"])
                        except Exception as e:
                            # Continue even if tag enrichment fails
                            pass
                    self.report(resp)
            else:
                self.error(f"API request failed with status code {r.status_code}: {r.text}")
                
        except Exception as e:
            self.error(f"Unexpected error in onion lookup: {str(e)}")

    def operations(self, raw):
        ops = []
        try:
            # Skip operations if raw is an error array
            if isinstance(raw, list):
                return []
                
            tags = set()
            if isinstance(raw, dict) and "tags" in raw and isinstance(raw["tags"], list):
                tags.update(str(t) for t in raw["tags"])
            tags.update({"source:ail-onion-lookup"})
            
            for t in sorted(tags):
                ops.append(self.build_operation("AddTagToArtifact", tag=t))

            # if self.csam_tag in tags:
            #     ops.append(self.build_operation("AddTagToArtifact", tag="risk:csam-linked"))
            #     ops.append(self.build_operation("AddTagToCase", tag="risk:csam-linked"))
            #     task_title = "Review CSAM-linked onion"
            #     task_desc = (
            #         "- Validate evidence handling (no download / safe preview)\n"
            #         "- Update blocklists / mail/ web proxies as applicable\n"
            #         "- Check prior sightings / related artifacts\n"
            #         "- Consider legal/notification procedures per policy\n"
            #         f"- Source: {self.base_url}\n"
            #     )
            #     ops.append(self.build_operation("CreateTask", title=task_title, description=task_desc))

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

            tags = []
            if isinstance(raw, dict) and "tags" in raw and isinstance(raw["tags"], list):
                tags = raw["tags"]

            found = False
            if isinstance(raw, dict):
                found = any(raw.get(k) for k in ("id", "first_seen", "last_seen", "titles", "languages", "tags"))
                
            # Status taxonomy
            taxonomies.append(
                self.build_taxonomy("info", namespace, "Status", "found" if found else "not-found")
            )

            # Detection count taxonomies for short reports
            if found and tags:
                detection_counts = self._count_detections(tags)
                
                # Total detections with descriptions
                if detection_counts['total'] > 0:
                    taxonomies.append(
                        self.build_taxonomy("info", namespace, "Detections", str(detection_counts['total']))
                    )
                
                # Notables detections
                if detection_counts['malicious'] > 0:
                    taxonomies.append(
                        self.build_taxonomy("suspicious", namespace, "Notables", str(detection_counts['malicious']))
                    )

            # Special case for CSAM
            if self.csam_tag in [str(t) for t in tags]:
                taxonomies.append(self.build_taxonomy("malicious", namespace, "CSAM", "linked"))

        except Exception:
            pass

        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    AILOnionLookup().run()