#!/usr/bin/env python3
# encoding: utf-8
import os
import json
import requests
from time import sleep
from cortexutils.analyzer import Analyzer
import urllib.parse


class APIRequestHandler(object):
    def __init__(self, api_url, apikey, polling, proxies):
        self.URL = api_url
        if self.URL:
            self.URL = self.URL.rstrip("/")
        self.apikey = apikey
        self.polling = polling
        self.proxies = proxies

    def check_file(self, filename, filepath):
        if os.path.exists(filepath):
            data = open(filepath, "rb")
            r = requests.post(
                "%s/file" % self.URL,
                headers={
                    "apikey": self.apikey,
                    "filename": filename,
                    "content-type": "application/octet-stream",
                },
                data=data,
                proxies=self.proxies,
            )
            if r.status_code == 200:
                data_id = json.loads(r.text).get("data_id", None)
            else:
                return {}
            percentage = 0
            while percentage != 100:
                if percentage == -1:
                    return {}
                sleep(self.polling)
                r = requests.get(
                    "%s/file/%s" % (self.URL, data_id),
                    headers={"apikey": self.apikey},
                    proxies=self.proxies,
                )
                if r.status_code == 200:
                    percentage = (
                        json.loads(r.text)
                        .get("scan_results", {})
                        .get("progress_percentage", -1)
                    )
            return json.loads(r.text)
        else:
            return {}

    def check_hash(self, hash):
        r = requests.get(
            "%s/hash/%s" % (self.URL, hash),
            headers={"apikey": self.apikey},
            proxies=self.proxies,
        )
        if r.status_code == 200:
            data = json.loads(r.text)
            if data.get(hash, None) == "Not Found":
                return {}
            return data
        return {}

    def check_reputation(self, data_type, data):
        r = requests.get(
            "%s/%s/%s" % (self.URL, data_type, urllib.parse.quote(data, safe='')),
            headers={"apikey": self.apikey},
            proxies=self.proxies,
        )
        if r.status_code == 200:
            data = json.loads(r.text)
            if data.get("success", False) == False:
                return {}
            return data
        return {}



class OPSWATMetadefender(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam(
            "config.service", None, "Service parameter is missing"
        )
        api_url = self.getParam("config.url", None, "Missing API url")
        apikey = self.getParam("config.key", None, "Missing API key")
        polling = self.getParam("config.polling", 10)
        proxies = self.get_param("config.proxy", None)

        self.request_handler = APIRequestHandler(api_url, apikey, polling, proxies)

    def summary(self, raw):
        taxonomies = []
        level = "info"
        if self.service in ("scan_cloud", "query_cloud", "reputation_cloud"): 
            namespace = "OPSWATMetadefender-Cloud"
        else:
            namespace = "OPSWATMetadefender-Core"
        if self.service in ("scan_cloud", "scan_core", "query_cloud", "query_core"):
            predicate = "Report"
            score = raw.get("scan_results", {}).get("scan_all_result_a", "No Info")
            score_no = raw.get("scan_results", {}).get("scan_all_result_i", 0)
            if score_no == 1:
                level = "malicious"
            elif score_no == 2:
                level = "suspicious"
            elif score_no in (3, 4, 6, 7):
                level = "info"
            elif score_no in (0, 5):
                level = "safe"
        elif self.service == 'reputation_cloud':
            predicate = "Reputation"
            score_no = raw.get("lookup_results", {}).get("detected_by", 0)
            score_total = len(raw.get("lookup_results", {}).get("sources", []))
            if score_no == 0:
                level = "safe"
            elif score_no <= 2:
                level = "suspicious"
            else:
                level = "malicious"
            score = "%d/%d" % (score_no, score_total)
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, score))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.service in ("query_cloud", "query_core"):
            if self.data_type == "hash":
                data = self.get_param("data", None, "Data is missing")
                rep = self.request_handler.check_hash(data)
                self.report(rep)
            else:
                self.error("Invalid data type")
        elif self.service in ("scan_cloud", "scan_core"):
            if self.data_type == "file":
                filename = self.get_param("filename", "noname.ext")
                filepath = self.get_param("file", None, "File is missing")
                rep = self.request_handler.check_file(filename, filepath)
                self.report(rep)
        elif self.service == 'reputation_cloud':
            if self.data_type in ("ip", "url", "domain"):
                data = self.get_param("data", None, "Data is missing")
                rep = self.request_handler.check_reputation(self.data_type, data)
                self.report(rep)                
        else:
            self.error("Invalid service")


if __name__ == "__main__":
    OPSWATMetadefender().run()
