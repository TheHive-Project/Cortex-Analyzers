#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.analyzer import Analyzer
from falconpy import OAuth2
from falconpy import Intel


class CrowdstrikeFalcon_ThreatIntel(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.client_id = self.get_param("config.client_id")
        self.client_secret = self.get_param("config.client_secret")
        self.base_url = self.get_param("config.base_url", "https://api.crowdstrike.com")
        self.include_deleted = self.get_param("config.include_deleted", False)
        self.limit = self.get_param("config.limit", 100)

    def _detect_hash_type(self, hash_value):
        """Detect hash type based on length"""
        hash_len = len(hash_value)
        if hash_len == 32:
            return "hash_md5"
        elif hash_len == 40:
            return "hash_sha1"
        elif hash_len == 64:
            return "hash_sha256"
        elif hash_len == 128:
            return "hash_sha512"
        else:
            return None

    def _build_filter(self, data_type, observable):
        """Build FQL filter based on data type and observable"""
        if data_type == 'hash':
            hash_type = self._detect_hash_type(observable)
            if hash_type:
                return f"type:'{hash_type}'+indicator:'{observable.upper()}'"
            else:
                # Search across all hash types if we can't determine
                return f"indicator:'{observable.upper()}'"
        elif data_type == 'domain':
            return f"type:'domain'+indicator:'{observable}'"
        elif data_type == 'ip':
            return f"type:'ip_address'+indicator:'{observable}'"
        elif data_type == 'url':
            return f"type:'url'+indicator:'{observable}'"
        else:
            return f"indicator:'{observable}'"

    def run(self):
        Analyzer.run(self)

        try:
            observable = self.get_data()

            auth = OAuth2(client_id=self.client_id, client_secret=self.client_secret, base_url=self.base_url)
            extra_headers = {
                "User-Agent": "strangebee-thehive/1.0"
            }
            intel = Intel(auth_object=auth, ext_headers=extra_headers)
            fql_filter = self._build_filter(self.data_type, observable)
            response = intel.query_indicator_entities(
                filter=fql_filter,
                limit=self.limit,
                include_deleted=self.include_deleted,
                sort="published_date|desc"
            )
            if 200 <= response["status_code"] < 300:
                indicators = response["body"].get("resources", [])
                result = {
                    "observable": observable,
                    "indicator_count": len(indicators),
                    "indicators": indicators
                }
                return self.report(result)
            else:
                errors = response["body"].get("errors", [])
                return self.error(f"Error querying threat intelligence: {errors}")

        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        taxonomies = []
        namespace = "CSFalcon"
        predicate = "TI"

        indicator_count = raw.get("indicator_count", 0)

        if indicator_count == 0:
            level = "safe"
            value = "No indicators found"
        else:
            # Determine level based on malicious confidence
            max_confidence = "unknown"
            threat_types = set()
            actors = set()

            for indicator in raw.get("indicators", []):
                confidence = indicator.get("malicious_confidence", "unknown")

                # Track the highest confidence level
                if confidence == "high":
                    max_confidence = "high"
                elif confidence == "medium" and max_confidence not in ["high"]:
                    max_confidence = "medium"
                elif confidence == "low" and max_confidence not in ["high", "medium"]:
                    max_confidence = "low"

                # Collect threat types and actors
                threat_types.update(indicator.get("threat_types", []))
                actors.update(indicator.get("actors", []))

            # Determine taxonomy level
            if max_confidence == "high":
                level = "malicious"
            elif max_confidence == "medium":
                level = "suspicious"
            elif max_confidence == "low":
                level = "suspicious"
            else:
                level = "info"

            value = f"{indicator_count} indicator(s) | Confidence: {max_confidence}"

            taxonomies.append(
                self.build_taxonomy(level, namespace, predicate, value)
            )

            # Add threat types if present
            if threat_types:
                predicate_threat = "ThreatTypes"
                value_threat = ", ".join(list(threat_types)[:3])  # Limit to 3
                taxonomies.append(
                    self.build_taxonomy(level, namespace, predicate_threat, value_threat)
                )

            # Add actors if present
            if actors:
                predicate_actor = "Actors"
                value_actor = ", ".join(list(actors)[:3])  # Limit to 3
                taxonomies.append(
                    self.build_taxonomy("info", namespace, predicate_actor, value_actor)
                )

        if not taxonomies:
            taxonomies.append(
                self.build_taxonomy(level, namespace, predicate, value)
            )

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []

        for indicator in raw.get("indicators", []):
            # Collect malware families and actors to use as tags
            malware_families = indicator.get("malware_families", [])
            actors = indicator.get("actors", [])

            # Build tags for related observables
            context_tags = ["crowdstrike-ti", "related"]
            if malware_families:
                context_tags.extend([f"malware:{mf}" for mf in malware_families])
            if actors:
                context_tags.extend([f"actor:{actor}" for actor in actors])

            # Extract related domains, IPs, and hashes with context tags
            relations = indicator.get("relations", [])
            for relation in relations:
                if relation.get("type") == "domain":
                    artifacts.append(
                        self.build_artifact(
                            "domain",
                            relation.get("indicator"),
                            tags=context_tags
                        )
                    )
                elif relation.get("type") == "ip_address":
                    artifacts.append(
                        self.build_artifact(
                            "ip",
                            relation.get("indicator"),
                            tags=context_tags
                        )
                    )
                elif relation.get("type") in ["hash_md5", "hash_sha1", "hash_sha256"]:
                    artifacts.append(
                        self.build_artifact(
                            "hash",
                            relation.get("indicator"),
                            tags=context_tags
                        )
                    )

            # Extract CVEs from vulnerabilities
            vulnerabilities = indicator.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                if vuln.startswith("CVE-"):
                    artifacts.append(
                        self.build_artifact(
                            "other",
                            vuln,
                            tags=["crowdstrike-ti", "vulnerability", "cve"]
                        )
                    )

        return artifacts

    def operations(self, raw):
        operations = []

        # Collect all unique malware families and actors across indicators
        malware_families = set()
        actors = set()

        for indicator in raw.get("indicators", []):
            malware_families.update(indicator.get("malware_families", []))
            actors.update(indicator.get("actors", []))

        # Add malware families as tags to artifacts
        for malware in malware_families:
            operations.append(
                self.build_operation("AddTagToArtifact", tag=f"malware:{malware}")
            )

        # Add actors as tags to artifacts
        for actor in actors:
            operations.append(
                self.build_operation("AddTagToArtifact", tag=f"actor:{actor}")
            )

        return operations


if __name__ == "__main__":
    CrowdstrikeFalcon_ThreatIntel().run()
