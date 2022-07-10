#!/usr/bin/env python3
# encoding: utf-8

# report -> domain

import os
import time
import hashlib
import magic
import tempfile
import mimetypes
import filetype
import json
import urllib
import urllib.parse

from datetime import datetime
from vt import Client, error
from cortexutils.analyzer import Analyzer
from base64 import urlsafe_b64encode, b64decode


class VirusTotalAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            "config.service", None, "Service parameter is missing"
        )
        self.virustotal_key = self.get_param(
            "config.key", None, "Missing VirusTotal API key"
        )
        self.polling_interval = self.get_param("config.polling_interval", 60)
        self.rescan_hash_older_than_days = self.get_param(
            "config.rescan_hash_older_than_days", None
        )
        self.highlighted_antivirus = self.get_param(
            "config.highlighted_antivirus", None
        )
        self.download_sample = self.get_param("config.download_sample", False)
        self.download_sample_if_highlighted = self.get_param(
            "config.download_sample_if_highlighted", False
        )
        self.obs_path = None
        self.proxies = self.get_param("config.proxy", None)
        self.vt = Client(apikey=self.virustotal_key, proxy=self.proxies)

    def get_file(self, hash):
        self.obs_path = "{}/{}".format(tempfile.gettempdir(), hash)
        with open(self.obs_path, "wb") as obs_file:
            self.vt.download_file(hash, obs_file)

    def file_to_sha256(self, file):
        sha256_hash = hashlib.sha256()
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def artifacts(self, raw):
        artifacts = []

        if self.obs_path:
            tags = ["autoImport:true"]
            # This will work only in scan/rescan workflow, not in download
            if self.highlighted_antivirus:
                for av in self.highlighted_antivirus:
                    category = (
                        raw["attributes"]
                        .get("last_analysis_results", {})
                        .get(av, {})
                        .get("category", None)
                    )
                    if category != "malicious" or category != "suspicious":
                        tags.append("to_{}".format(av))
            artifacts.append(self.build_artifact("file", self.obs_path, tags=tags))

        for ioc_type in raw.get("iocs"):
            for ioc in raw.get("iocs").get(ioc_type):
                artifacts.append(self.build_artifact(ioc_type, ioc.get("data"), tags=ioc.get("tags")))

        return artifacts

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "VT"
        predicate = "GetReport"
        value = "0"
        stats_field = "last_analysis_stats"
        results_field = "last_analysis_results"
        date_field = "last_analysis_date"

        if self.service == "scan" or self.service == "rescan":
            stats_field = "stats"
            results_field = "results"
            date_field = "date"

        if self.service == "scan":
            predicate = "Scan"
        elif self.service == "rescan":
            predicate = "Rescan"
        elif self.service == "download":
            return {"taxonomies": taxonomies}

        result = {"has_result": True}

        if "id" not in raw:
            result["has_result"] = False

        if stats_field in raw["attributes"]:
            result["malicious"] = raw["attributes"][stats_field].get("malicious", 0)
            result["suspicious"] = raw["attributes"][stats_field].get("suspicious", 0)
            result["type-unsupported"] = raw["attributes"][stats_field].get(
                "type-unsupported", 0
            )
            result["confirmed-timeout"] = raw["attributes"][stats_field].get(
                "confirmed-timeout", 0
            )
            result["timeout"] = raw["attributes"][stats_field].get("timeout", 0)
            result["failure"] = raw["attributes"][stats_field].get("failure", 0)
            result["undetected"] = raw["attributes"][stats_field].get("undetected", 0)

            total = 0
            for category, value in raw["attributes"][stats_field].items():
                total += value
            result["total"] = total

        if date_field in raw["attributes"]:
            result["scan_date"] = raw["attributes"][date_field]

        if self.service == "get":
            if "last_analysis_stats" in raw["attributes"]:
                result["scans"] = len(raw["attributes"]["last_analysis_results"])
                value = "{}/{}".format(
                    result["malicious"] + result["suspicious"], result["total"]
                )
                if result["malicious"] > 0:
                    level = "malicious"
                elif result["suspicious"] > 0:
                    level = "suspicious"
                elif (
                    result["type-unsupported"] > 1
                    or result["confirmed-timeout"] > 1
                    or result["timeout"] > 1
                    or result["failure"] > 1
                    or result["undetected"]
                ):
                    level = "info"
                else:
                    level = "safe"
                taxonomies.append(
                    self.build_taxonomy(level, namespace, predicate, value)
                )

            data_type = "files"
            if raw["type"] == "url":
                data_type = "urls"
            elif raw["type"] == "domain":
                data_type = "domains"
            elif raw["type"] == "ip_address":
                data_type = "ip_addresses"

            if data_type in ["files", "urls"]:
                try:
                    result["resolutions"] = self.vt.get_object(
                        "/{}/{}/{}".format(data_type, raw["id"], "contacted_domains")
                    ).to_dict()
                    value = "{} resolution(s)".format(result["meta"]["count"])
                    if result["meta"]["count"] == 0:
                        level = "safe"
                    elif result["meta"]["count"] < 5:
                        level = "suspicious"
                    else:
                        level = "malicious"
                    taxonomies.append(
                        self.build_taxonomy(level, namespace, predicate, value)
                    )
                except Exception:
                    pass  # Premium api key required

            
            if data_type in ["ip_addresses", "domains"]:
                try:
                    result["resolutions"] = self.vt.get_object(
                        "/{}/{}/{}".format(data_type, raw["id"], "resolutions")
                    ).to_dict()
                    value = "{} resolution(s)".format(result["meta"]["count"])
                    if result["meta"]["count"] == 0:
                        level = "safe"
                    elif result["meta"]["count"] < 5:
                        level = "suspicious"
                    else:
                        level = "malicious"
                    taxonomies.append(
                        self.build_taxonomy(level, namespace, predicate, value)
                    )
                except Exception:
                    pass  # Premium api key required

            if data_type in ["files"]:
                try:
                    result["embedded_urls"] = self.vt.get_object(
                        "/{}/{}/{}".format(data_type, raw["id"], "embedded_urls")
                    ).to_dict()
                    value = "{} embedded_url(s)".format(result["meta"]["count"])
                    if result["meta"]["count"] == 0:
                        level = "safe"
                    elif result["meta"]["count"] < 5:
                        level = "suspicious"
                    else:
                        level = "malicious"
                    taxonomies.append(
                        self.build_taxonomy(level, namespace, predicate, value)
                    )
                except Exception:
                    pass  # Premium api key required

            if data_type in ["files", "ip_addresses", "domains"]:
                try:
                    result["downloaded_files"] = self.vt.get_object(
                        "/{}/{}/{}".format(data_type, raw["id"], "downloaded_files")
                    ).to_dict()
                    value = "{} downloaded_file(s)".format(result["meta"]["count"])
                    if result["meta"]["count"] == 0:
                        level = "safe"
                    elif result["meta"]["count"] < 5:
                        level = "suspicious"
                    else:
                        level = "malicious"
                    taxonomies.append(
                        self.build_taxonomy(level, namespace, predicate, value)
                    )
                except Exception:
                    pass  # Premium api key required

        if self.service in ["scan", "rescan"]:
            if "stats" in raw["attributes"]:
                result["scans"] = len(raw["attributes"]["last_analysis_results"])
                value = "{}/{}".format(
                    result["malicious"] + result["suspicious"], result["total"]
                )
                if result["malicious"] > 0:
                    level = "malicious"
                elif result["suspicious"] > 0:
                    level = "suspicious"
                elif (
                    result["type-unsupported"] > 1
                    or result["confirmed-timeout"] > 1
                    or result["timeout"] > 1
                    or result["failure"] > 1
                    or result["undetected"]
                ):
                    level = "info"
                else:
                    level = "safe"
                taxonomies.append(
                    self.build_taxonomy(level, namespace, predicate, value)
                )

        if self.highlighted_antivirus:
            for av in (av for av in self.highlighted_antivirus if av):
                category = (
                    raw["attributes"][results_field].get(av, {}).get("category", None)
                )
                if category != "malicious" or category != "suspicious":
                    taxonomies.append(
                        self.build_taxonomy("info", namespace, av, "Not detected!")
                    )

        return {"taxonomies": taxonomies}

    def run(self):
        results = dict()
        iocs = dict()
        iocs['ip'] = list()
        iocs['domain'] = list()
        iocs['url'] = list()
        iocs['other'] = list()
        
        if self.service == "scan":  # OK
            if self.data_type == "file":
                filepath = self.get_param("file", None, "File is missing")
                with open(filepath, "rb") as f:
                    resp = self.vt.scan_file(file=f, wait_for_completion=True)
                    results = resp.to_dict()
                    file_hash = b64decode(results.get("id")).decode().split(':')[0]
                    self.get_contacted_domains(results, iocs, "files", file_hash)
                    self.get_contacted_ips(results, iocs, "files", file_hash)
                    self.get_contacted_urls(results, iocs, "files", file_hash)

            elif self.data_type == "url":
                url = self.get_param("data", None, "Data is missing")
                resp = self.vt.scan_url(url=url, wait_for_completion=True)
                results = resp.to_dict()
                url_b64 = results.get("id").split("-")[1]
                self.get_contacted_domains(results, iocs, "urls", url_b64)
                self.get_contacted_ips(results, iocs, "urls", url_b64)
                self.get_last_serving_ip_address(results, iocs, "urls", url_b64)
            else:
                self.error("Invalid data type")

        elif self.service == "rescan":
            if self.data_type == "hash":
                data = self.get_param("data", None, "Data is missing")
                resp = self.vt.post("/files/{}/analyse".format(data)).text()
                results = json.loads(resp)
                self.get_contacted_domains(results, iocs, "files", data)
                self.get_contacted_ips(results, iocs, "files", data)
                self.get_contacted_urls(results, iocs, "files", data)
            else:
                self.error("Invalid data type")

        elif self.service == "download":
            if self.data_type == "hash":
                data = self.get_param("data", None, "Data is missing")
                self.get_file(data)
                self.report({"message": "file downloaded"})

        elif self.service == "get":
            if self.data_type == "domain" or self.data_type == "fqdn":
                data = self.get_param("data", None, "Data is missing")
                results = self.vt.get_object("/domains/{}".format(data)).to_dict()

            elif self.data_type == "ip":
                data = self.get_param("data", None, "Data is missing")
                results = self.vt.get_object("/ip_addresses/{}".format(data)).to_dict()
                self.get_urls(results, iocs, data)

            elif self.data_type == "file":
                filepath = self.get_param("file", None, "File is missing")
                with open(filepath, "rb") as f:
                    file_hash = self.file_to_sha256(f)
                    results = self.vt.get_object(
                        "/files/{}".format(file_hash)
                    ).to_dict()
                    self.get_contacted_domains(results, iocs, "files", file_hash)
                    self.get_contacted_ips(results, iocs, "files", file_hash)
                    self.get_contacted_urls(results, iocs, "files", file_hash)

            elif self.data_type == "hash":
                data = self.get_param("data", None, "Data is missing")
                results = self.vt.get_object("/files/{}".format(data)).to_dict()
                self.get_contacted_domains(results, iocs, "files", data)
                self.get_contacted_ips(results, iocs, "files", data)
                self.get_contacted_urls(results, iocs, "files", data)

            elif self.data_type == "url":
                url = self.get_param("data", None, "Data is missing")
                url_b64 = urlsafe_b64encode(url.encode()).decode().split("=")[0]
                results = self.vt.get_object("/urls/{}".format(url_b64)).to_dict()
                self.get_contacted_domains(results, iocs, "urls", url_b64)
                self.get_contacted_ips(results, iocs, "urls", url_b64)
                self.get_last_serving_ip_address(results, iocs, "urls", url_b64)
            else:
                self.error("Invalid data type")
            self.get_yararuleset(results, iocs)
            self.get_ids_results(results, iocs)

            # if aged and enabled rescan
            if self.data_type == "hash" and self.rescan_hash_older_than_days:
                if (
                    datetime.fromtimestamp(results["attributes"]["last_analysis_date"])
                    - datetime.now()
                ).days > self.rescan_hash_older_than_days:
                    filepath = self.get_param("file", None, "File is missing")
                    with open(filepath, "rb") as f:
                        self.vt.scan_file(file=f, wait_for_completion=True)

            # download if hash, dangerous and not seen by av
            if (
                self.data_type == "hash"
                and (results.get("response_code", None) == 1)
                and (
                    results["attributes"]["last_analysis_stats"].get("malicious", 0)
                    >= 5
                )
                and (
                    self.download_sample
                    or (
                        self.download_sample_if_highlighted
                        and self.highlighted_antivirus
                        and any(
                            [
                                results.get("scans", {})
                                .get(av, {})
                                .get("detected", None)
                                == False
                                for av in self.highlighted_antivirus
                            ]
                        )
                    )
                )
            ):
                self.get_file(data)
        else:
            self.error("Invalid service")
        results['iocs'] = iocs
        self.report(results)

    def get_yararuleset(self, results, iocs):
        for yara_result in results["attributes"].get( "crowdsourced_yara_results", []):
            yara_ruleset = self.vt.get_object(
                        "/yara_rulesets/{}".format(yara_result["ruleset_id"])
                        ).to_dict()
            iocs["other"].append({
                "data": yara_ruleset["attributes"]["rules"],
                "tags": [
                    "detection:YARA",
                    "autoImport:false",
                    "ruleset:{}".format(yara_ruleset["attributes"]["name"])
                ]
            })

    def get_ids_results(self, results, iocs):
        for ids_result in results["attributes"].get("crowdsourced_ids_results", []):
            iocs["other"].append({
                "data": ids_result["rule_raw"],
                "tags": [
                    "detection:IDS",
                    "autoImport:false",
                    "rule-src:{}".format(ids_result["rule_source"])
                ]
            })

    def get_contacted_ips(self, results, iocs, data_type, data):
        try:
            result = self.vt.get_json(
                "/{}/{}/{}".format(data_type, data, "contacted_ips")
            )
            if not "relations" in results:
                results["relations"] = {}
            results['relations']['contacted_ips'] = result
            for ip in result['data']:
                iocs["ip"].append({
                    "data": ip["id"],
                    "tags": ["known-relationship:contacted-ip", "autoImport:false"]
                })
        except Exception:
            pass #Premium api required for urls

    def get_contacted_domains(self, results, iocs, data_type, data):
        try:
            result = self.vt.get_json(
                "/{}/{}/{}".format(data_type, data, "contacted_domains")
            )
            if not "relations" in results:
                results["relations"] = {}
            results['relations']['contacted_domains'] = result
            for domain in result['data']:
                iocs["domain"].append({
                    "data": domain["id"],
                    "tags": ["known-relationship:contacted-domain", "autoImport:false"]
                })
        except Exception:
            pass #Premium api required for urls

    def get_contacted_urls(self, results, iocs, data_type, data):
        result = self.vt.get_json(
            "/{}/{}/{}".format(data_type, data, "contacted_urls")
        )
        if not "relations" in results:
            results["relations"] = {}
        results['relations']['contacted_urls'] = result
        for url in result['data']:
            iocs["url"].append({
                "data": url['attributes']['url'],
                "tags": ["known-relationship:contacted-urls", "autoImport:false"]
            })

    def get_last_serving_ip_address(self, results, iocs, data_type, data):
        result = self.vt.get_json(
            "/{}/{}/{}".format(data_type, data, "last_serving_ip_address")
        )
        if not "relations" in results:
            results["relations"] = {}
        results['relations']['last_serving_ip_address'] = result
        iocs["ip"].append({
            "data": result['data']["id"],
            "tags": ["known-relationship:last_serving_ip_address", "autoImport:false"]
        })

    def get_urls(self, results, iocs, data):
        try:
            result = self.vt.get_json(
                "/{}/{}/{}".format("ip_addresses", data, "urls")
            )
            if not "relations" in results:
                results["relations"] = {}
            results['relations']['urls'] = result
            for url in result['data']:
                iocs["url"].append({
                    "data": url['attributes']['url'],
                    "tags": ["known-relationship:url", "autoImport:false"]
                })
        except Exception:
            pass #Premium api required

if __name__ == "__main__":
    VirusTotalAnalyzer().run()
