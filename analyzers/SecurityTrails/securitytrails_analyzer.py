#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
from securitytrails import SecurityTrailsException, SecurityTrails


class SecurityTrailsAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            "config.service", None, "SecurityTrails service is missing")

        self.api_key = self.get_param(
            "config.api_key", None, "SecurityTrails API key is missing")

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "ST"

        if self.service == "passive_dns":
            predicate = "PassiveDNS"
            total = 0
            if "record_count" in raw and raw["record_count"]:
                total = raw["record_count"]

            if total < 2:
                value = "{} record".format(total)
            else:
                value = "{} records".format(total)
        elif self.service == "whois":
            predicate = "Whois"
            name = "N/A"
            email = "N/A"

            if "registrarName" in raw and raw["registrarName"]:
                name = raw["registrarName"]

            if "contactEmail" in raw and raw["contactEmail"]:
                email = raw["contactEmail"]

            value = "Registrar name: {} / Contact email: {}".format(
                name, email)

        taxonomies.append(
            self.build_taxonomy(level, namespace, predicate, value)
        )

        return {"taxonomies": taxonomies}

    def run(self):
        data = self.get_data()

        try:
            st = SecurityTrails(api_key=self.api_key)
            # passive dns service
            if self.service == "passive_dns":
                result = st.passive_dns(data)
                self.report(result)
            elif self.service == "whois":
                result = st.whois(data)
                self.report(result)
            else:
                self.error("Unknown SecurityTrails service")

        except SecurityTrailsException as e:
            self.error(str(e))


if __name__ == "__main__":
    SecurityTrailsAnalyzer().run()
