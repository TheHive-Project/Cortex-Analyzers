#!/usr/bin/env python3
# -*- coding: utf-8 -*
from cortexutils.analyzer import Analyzer
import requests


class LastInfoSec(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param(
            "config.apiKey", None, "LastInfoSec API KEY is required"
        )
        self.observable_value = self.get_param("data", None, "Data is missing")

    def run(self):
        if self.data_type == "hash":
            url = "https://api.client.lastinfosec.com/v2/lis/search_hash/{0}?api_key={1}".format(
                self.observable_value, self.api_key
            )
        elif self.data_type == "domain":
            url = "https://api.client.lastinfosec.com/v2/lis/search_host/{0}?api_key={1}".format(
                self.observable_value, self.api_key
            )
        else:
            self.error("{} not supported".format(self.data_type))
        useragent = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) Gecko/20100101 Firefox/41.0"
        }
        response = requests.get(url, headers=useragent)
        info = self.check_response(response)

        additional = {}
        main = {}
        main_hash = {}
        urls = []
        records = {"IOCs": []}

        if self.data_type == "hash":
            for item in info["message"][0]["IOCs"]:
                item.update(item.pop("MetaData", None))
                if item["Value"] == self.observable_value:
                    main = item
                elif item["Type"] in ["MD5", "SHA1", "SHA256"]:
                    additional[item["Type"]] = item["Value"]
                else:
                    records["IOCs"].append(item)
            main.update(additional)
            records["IOCs"].append(main)
        elif self.data_type == "domain":
            for item in info["message"][0]["IOCs"]:
                item.update(item.pop("MetaData", None))
                if item["Value"] == self.observable_value:
                    main = item
                elif item["Type"] == "URL":
                    urls.append({"url": item["Value"], "tags": item["Tags"]})
                elif item["Type"] in ["MD5", "SHA1", "SHA256"]:
                    if len(main_hash) == 0:
                        main_hash = item
                    else:
                        additional[item["Type"]] = item["Value"]

            main["urls"] = urls
            records["IOCs"].append(main)
            if len(main_hash) > 0:
                main_hash.update(additional)
                records["IOCs"].append(main_hash)

        self.report(records)

    def check_response(self, response):
        if response.status_code != 200:
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
        namespace = "LastInfoSec"
        predicate = "GetReport"
        value = 0
        data = next(
            (ioc for ioc in raw["IOCs"] if ioc["Value"] == self.observable_value), None
        )
        if data is not None:
            level = data["Risk"].lower()
            if level == "malicious":
                value = 86
            elif level == "high suspicious":
                value = 71
                level = "suspicious"
            else:
                value = 31

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    LastInfoSec().run()
