#!/usr/bin/env python3
# -*- coding: utf-8 -*
from cortexutils.analyzer import Analyzer
import requests


class GatewatcherCTI(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param("config.apiKey", None, "Gatewatcher CTI API KEY is required")
        self.extended_report = self.get_param("config.extendedReport", None, "Please set the Extended Report option")
        self.max_relations = self.get_param("config.maxRelations", None)
        self.observable_value = self.get_param("data", None, "Data is missing")
        self.data_type = self.get_param("dataType", None, "Data type is missing")
        self.base_url = "https://api.client.lastinfosec.com/v2/"
        self.headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) Gecko/20100101 Firefox/41.0"}

    def _IOCs_search(self):
        response = requests.post(
            url=f"{self.base_url}lis/search",
            headers=self.headers,
            params={"api_key": self.api_key, "extended_report": self.extended_report},
            json={"value": self.observable_value},
        )
        info = self.check_response(response)

        additional = {}
        main = {}
        records = {"IOCs": [], "IsOnGw": True}

        if response.status_code == 422:
            records["IsOnGw"] = False
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
                    if total_found_relations == len(relations) or (
                        has_max and total_found_relations >= self.max_relations
                    ):
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
                records["IsOnGw"] = False
        return records

    def _get_by_ip(self):
        response = requests.get(
            url=f"{self.base_url}lis/ip/get_by_ip/{self.observable_value}",
            headers=self.headers,
            params={"api_key": self.api_key, "headers": False},
        )
        info = self.check_response(response)
        if info.get("Score") == "Unknown":
            info["IsOnGw"] = False
        else:
            info["IsOnGw"] = True
        return info

    def _get_by_email(self):
        # TODO : check why headers false is always on 'InProgress' status on Cortex
        response = requests.get(
            url=f"{self.base_url}lis/leaked_emails/get_by_email/{self.observable_value}",
            headers=self.headers,
            params={"api_key": self.api_key, "headers": True},
        )
        info = self.check_response(response)
        # get only data of the request
        data = info.get("message")
        if len(data) < 1:
            return {"Value": self.observable_value, "IsOnGw": False}
        else:
            result = data[0]
            result["IsOnGw"] = True
            # Return number of passwords
            if result.get("Passwords") is not None:
                result["totalPasswords"] = len(result["Passwords"])
            return result

    def run(self):
        if self.data_type == "ip":
            records = self._get_by_ip()
        elif self.data_type == "mail":
            records = self._get_by_email()
        else:
            records = self._IOCs_search()
        records["DataType"] = self.data_type
        self.report(records)

    def check_response(self, response):
        if response.status_code not in [200, 422]:
            try:
                result = response.json()
                if "detail" in result and "details" in result["detail"] and "error" in result["detail"]["details"][0]:
                    self.error(f'Bad status: {response.status_code}. {result["detail"]["details"][0]["error"]}')
                else:
                    self.error(f"Bad status: {response.status_code}")
            except Exception:
                self.error(f"Bad status: {response.status_code}")
        else:
            try:
                result = response.json()
                return result
            except Exception as ex:
                self.error(f"Bad Response: {ex}")

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Gatewatcher CTI"
        predicate = "GetReport"
        value = "not found"
        if self.data_type == "ip":
            score = raw.get("Score")
            if score == "Suspicious":
                level = "suspicious"
                value = 41
            elif score == "Low suspicious":
                value = 31
            elif score == "Past suspicious":
                value = 21
        elif self.data_type == "mail":
            # If no "creation date", api result is empty --> Email is not leaked
            if raw.get("CreationDate") is None:
                value = "not leaked"
            else:
                value = "leaked"
        else:
            data = next((ioc for ioc in raw["IOCs"] if ioc["Value"] == self.observable_value), None)
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
