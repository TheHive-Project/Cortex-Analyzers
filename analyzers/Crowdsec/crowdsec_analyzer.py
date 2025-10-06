#!/usr/bin/env python3

from cortexutils.analyzer import Analyzer
from crowdsec_api import Crowdsec


class CrowdsecAnalyzer(Analyzer):
    def __init__(self, job_directory=None):
        Analyzer.__init__(self, job_directory)
        self.crowdsec_key = self.get_param(
            "config.api_key", None, "Missing Crowdsec API key"
        )
        self.taxonomy_reputation = self.get_param(
            "config.taxonomy_reputation", True, None
        )
        self.taxonomy_as_name = self.get_param("config.taxonomy_as_name", False, None)
        self.taxonomy_ip_range_score = self.get_param(
            "config.taxonomy_ip_range_score", False, None
        )
        self.taxonomy_last_seen = self.get_param(
            "config.taxonomy_last_seen", False, None
        )
        self.taxonomy_attack_details = self.get_param(
            "config.taxonomy_attack_details", False, None
        )
        self.taxonomy_behaviors = self.get_param(
            "config.taxonomy_behaviors", True, None
        )
        self.taxonomy_mitre_techniques = self.get_param(
            "config.taxonomy_mitre_techniques", False, None
        )
        self.taxonomy_cves = self.get_param("config.taxonomy_cves", True, None)
        self.taxonomy_not_found = self.get_param(
            "config.taxonomy_not_found", True, None
        )
        self.crowdsec_client = None

    def summary(self, raw):
        taxonomies = []
        namespace = "Crowdsec"
        levelinfo = "info"
        levelorange = "suspicious"
        levelgreen = "safe"
        levelred = "malicious"

        if self.taxonomy_reputation and "reputation" in raw:
            level = (
                levelred
                if raw["reputation"] == "malicious"
                else (
                    levelorange
                    if raw["reputation"] == "suspicious"
                    else levelgreen if raw["reputation"] == "safe" else levelinfo
                )
            )
            taxonomies.append(
                self.build_taxonomy(level, namespace, "Reputation", raw["reputation"])
            )

        if self.taxonomy_as_name and "as_name" in raw:
            taxonomies.append(
                self.build_taxonomy(levelinfo, namespace, "ASN", raw["as_name"])
            )

        if self.taxonomy_ip_range_score and "ip_range_score" in raw:
            taxonomies.append(
                self.build_taxonomy(
                    levelinfo, namespace, "Score", raw["ip_range_score"]
                )
            )

        if self.taxonomy_last_seen and "history" in raw:
            taxonomies.append(
                self.build_taxonomy(
                    levelinfo, namespace, "LastSeen", raw["history"]["last_seen"]
                )
            )

        if self.taxonomy_attack_details and "attack_details" in raw:
            for attack in raw["attack_details"]:
                taxonomies.append(
                    self.build_taxonomy(
                        levelorange, namespace, "Attack", attack["name"]
                    )
                )

        if self.taxonomy_behaviors and "behaviors" in raw:
            for behavior in raw["behaviors"]:
                taxonomies.append(
                    self.build_taxonomy(
                        levelorange, namespace, "Behavior", behavior["name"]
                    )
                )

        if self.taxonomy_mitre_techniques and "mitre_techniques" in raw:
            for mitre in raw["mitre_techniques"]:
                taxonomies.append(
                    self.build_taxonomy(levelorange, namespace, "Mitre", mitre["name"])
                )

        if self.taxonomy_cves and "cves" in raw:
            for cve in raw["cves"]:
                taxonomies.append(
                    self.build_taxonomy(levelorange, namespace, "CVE", cve)
                )

        if (
            self.taxonomy_not_found
            and "reputation" not in raw
            and "attack_details" not in raw
        ):
            taxonomies.append(
                self.build_taxonomy(levelgreen, namespace, "Threat", "Not found")
            )

        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)
        try:
            self.crowdsec_client = Crowdsec(self.crowdsec_key)
            data = self.get_param("data", None, "Data is missing")
            results = self.crowdsec_client.summary(data, self.data_type)

            self.report(results)

        except Exception:
            pass


if __name__ == "__main__":
    CrowdsecAnalyzer().run()
