#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import ipinfo


class IPinfoAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            "config.service", None, "IPinfo service is missing")

        self.api_key = self.get_param(
            "config.api_key", None, "IPinfo API key is missing")

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "IPinfo"

        if self.service == "details":
            country = raw.get("country")
            if country:
                taxonomies.append(
                    self.build_taxonomy(level, namespace, "Country", country)
                )

            asn = raw.get("asn")
            if asn and asn.get("asn"):
                taxonomies.append(
                    self.build_taxonomy(
                        level, namespace, "ASN", asn.get("asn"))
                )

        return {"taxonomies": taxonomies}

    def run(self):
        data = self.get_data()

        try:
            handler = ipinfo.getHandler(access_token=self.api_key,ip_address=data)

            if self.service == "details":
                result = handler.getDetails(data)
                self.report(result.all)
            else:
                self.error("Unknown IPinfo service")

        except :
            self.error("Error")


if __name__ == "__main__":
    IPinfoAnalyzer().run()
