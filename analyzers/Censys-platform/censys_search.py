#!/usr/bin/env python3
from censys_platform import SDK
from cortexutils.analyzer import Analyzer


class CensysAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.__oid = self.get_param(
            "config.oid",
            None,
            "No Organization ID in Censys given. Please add it to the cortex configuration.",
        )
        self.__api_key = self.get_param(
            "config.key",
            None,
            "No API-Key for Censys given. Please add it to the cortex configuration.",
        )
        self.__per_page = self.get_param("parameters.max_records", 100)
        self.__pages = self.get_param("parameters.pages", 200)
        self.SDK = SDK(personal_access_token=self.__api_key, organization_id=self.__oid)

    def search(self, search):
        """
        Searches for hosts in IPv4 base

        :param flatten: If the result is nested or not
        :param max_records: max records to get from censys
        :param search:search as string
        :param censys_fields: fields to get from censys
        :type search: str
        :type max_records: int
        :type censys_fields: list
        :type flatten: bool
        :return: dict
        """
        sdk_client = self.SDK
        fields = [
            "host.services.port",
            "host.ip",
            "host.services.cert.parsed.signature.self_signed",
            "host.services.cert.parsed.issuer.common_name",
            "host.services.cert.parsed.subject.common_name",
            "web.hostname",
            "web.ip",
            "web.cert.parsed.signature.self_signed",
            "web.cert.parsed.subject.common_name",
            "web.cert.parsed.issuer.common_name",
            "cert.valided_at",
            "cert.names",
            "cert.parsed.subject_dn",
            "cert.fingerprint_sha1",
            "cert.fingerprint_sha256",
        ]

        with sdk_client as platform:
            page_token = ""
            hits = []

            for i in range(self.__pages):
                res = platform.global_data.search(
                    search_query_input_body={
                        "query": search,
                        "page_size": self.__per_page,
                        "fields": fields,
                        "page_token": page_token,
                    }
                )

                for elem in res.result.result.hits:
                    hits.append(elem.model_dump())
                page_token = res.result.result.next_page_token

                if not page_token:
                    break
            return hits

    def run(self):
        try:
            if self.data_type == "other":
                matches = self.search(self.get_data())
                self.report({"matches": list(matches)})
            else:
                self.error(
                    "Data type not supported. Please use this analyzer with data types hash, ip or domain."
                )
        except Exception as e:
            self.report({"message": f"Error: {repr(e)}."})

    def summary(self, raw):
        taxonomies = []
        if "matches" in raw:
            result_count = len(raw.get("matches", []))
            taxonomies.append(
                self.build_taxonomy(
                    "info", "Censys Platform search", "results", result_count
                )
            )

        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    CensysAnalyzer().run()
