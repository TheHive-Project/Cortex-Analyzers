#!/usr/bin/env python3
# -*- coding: utf-8 -*
from cortexutils.analyzer import Analyzer
import requests


class GatewatcherCTI(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param(
            "config.apiKey", None, "Gatewatcher CTI API KEY is required"
        )
        self.extended_report = self.get_param(
            "config.extendedReport", None, "Please set the Extended Report option"
        )
        self.max_relations= self.get_param(
            "config.maxRelations", None
        )
        self.observable_value = self.get_param("data", None, "Data is missing")

    def run(self):
        url = f"https://api.client.lastinfosec.com/v2/lis/search?api_key={self.api_key}"
        if not self.extended_report:
            url = f"{url}&extended_report=false"
        data = {"value" : self.observable_value}
        useragent = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) Gecko/20100101 Firefox/41.0"
        }
        response = requests.post(url, headers=useragent, json=data)
        info = self.check_response(response)

        additional = {}
        main = {}
        records = {"IOCs": [], "is_on_gw": True}

        if response.status_code == 422:
            records["is_on_gw"] = False
        else:
            relations = []
            for item in info["message"][0]["IOCs"]:
                item.update(item.pop("MetaData", None))
                if item["Value"] == self.observable_value:
                    main = item
                    relations = item.get("Relations", [])
                    break

            if len(relations) > 0:
                has_max = True
                if self.max_relations == -1:
                    has_max = False
                total_found_relations = 0
                for item in info["message"][0]["IOCs"]:
                    if (total_found_relations == len(relations) or
                            (has_max and total_found_relations >= self.max_relations)):
                        break

                    if item["IocId"] in relations:
                        total_found_relations += 1

                        if all(x in ["MD5", "SHA1", "SHA256"] for x in [item["Type"], main["Type"]]):
                            if item["Type"] not in additional:
                                additional[item["Type"]] = item["Value"]
                            else:
                                additional[item["Type"]] = None
                        elif item["Type"] in ["URL", "Host", "MD5", "SHA1", "SHA256"]:
                            records["IOCs"].append(item)

            additional = {k: v for k, v in additional.items() if v is not None}
            main.update(additional)
            records["IOCs"].insert(0, main)
            if len(records["IOCs"]) == 1 and records["IOCs"][0]["Risk"].lower() == "unknown":
                records["is_on_gw"] = False

        self.report(records)

    def check_response(self, response):
        if response.status_code not in [200, 422]:
            try:
                result = response.json()
                if (
                    "detail" in result
                    and "details" in result["detail"]
                    and "error" in result["detail"]["details"][0]
                ):
                    self.error(
                        "Bad status: {0}. {1}".format(
                            response.status_code,
                            result["detail"]["details"][0]["error"],
                        )
                    )
                else:
                    self.error("Bad status: {0}".format(response.status_code))
            except Exception as ex:
                self.error("Bad status: {0}".format(response.status_code))
        else:
            try:
                result = response.json()
                return result
            except Exception as ex:
                self.error("Bad Response: {0}".format(ex))

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Gatewatcher CTI"
        predicate = "GetReport"
        value = "not found"
        data = next(
            (ioc for ioc in raw["IOCs"] if ioc["Value"] == self.observable_value), None
        )
        if data is not None:
            level = data["Risk"].lower()
            if level == "malicious":
                value = 100
            elif level == "high suspicious":
                value = 75
            elif level == "suspicious":
                value = 60

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    GatewatcherCTI().run()
