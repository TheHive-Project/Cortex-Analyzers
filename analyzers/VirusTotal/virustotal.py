#!/usr/bin/env python3
# encoding: utf-8

import os
import time
import hashlib
import magic
import tempfile
import mimetypes
import filetype

from datetime import datetime
from virus_total_apis import PublicApi, PrivateApi
from cortexutils.analyzer import Analyzer


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
        if (
            self.download_sample
            or self.download_sample_if_highlighted
            or self.service == "download"
        ):
            self.vt_pay = PrivateApi(self.virustotal_key, self.proxies)
        self.vt = PublicApi(self.virustotal_key, self.proxies)

    def get_file(self, hash):
        self.obs_path = "{}/{}".format(tempfile.gettempdir(), hash)
        response = self.vt_pay.get_file(hash)
        if response.get("response_code", None) == 200:
            with open(self.obs_path, "wb") as f:
                f.write(response["results"])
            kind = filetype.guess(self.obs_path)
            if kind and kind.extension != None:
                os.rename(self.obs_path, "{}.{}".format(self.obs_path, kind.extension))
                self.obs_path = "{}.{}".format(self.obs_path, kind.extension)

    def wait_file_report(self, id):
        results = self.check_response(self.vt.get_file_report(id))
        code = results.get("response_code", None)
        if code == 1:
            if self.data_type == "hash" and (
                self.download_sample
                or (
                    self.download_sample_if_highlighted
                    and self.highlighted_antivirus
                    and any(
                        [
                            results.get("scans", {}).get(av, {}).get("detected", None)
                            == False
                            for av in self.highlighted_antivirus
                        ]
                    )
                )
            ):
                self.get_file(self.get_param("data", None, "Data is missing"))
            self.report(results)
        else:
            time.sleep(self.polling_interval)
            self.wait_file_report(id)

    def wait_url_report(self, id):
        results = self.check_response(self.vt.get_url_report(id))
        code = results.get("response_code", None)
        if code == 1 and (results.get("scan_id") == id):
            self.report(results)
        else:
            time.sleep(self.polling_interval)
            self.wait_url_report(id)

    def check_response(self, response):
        if type(response) is not dict:
            self.error("Bad response : " + str(response))
        status = response.get("response_code", -1)
        if status == 204:
            self.error("VirusTotal api rate limit exceeded (Status 204).")
        if status != 200:
            self.error("Bad status : " + str(status))
        results = response.get("results", {})
        if "Missing IP address" in results.get("verbose_msg", ""):
            results["verbose_msg"] = "IP address not available in VirusTotal"
        return results

        # 0 => not found
        # -2 => in queue
        # 1 => ready

    def read_scan_response(self, response, func):
        results = self.check_response(response)
        code = results.get("response_code", None)
        scan_id = results.get("scan_id", None)
        if code == 1 and scan_id is not None:
            func(scan_id)
        else:
            self.error("Scan not found")

    def artifacts(self, raw):
        artifacts = []
        if self.obs_path:
            tags = []
            # This will work only in scan/rescan workflow, not in download only
            if self.highlighted_antivirus:
                for av in self.highlighted_antivirus:
                    detected = raw.get("scans", {}).get(av, {}).get("detected", None)
                    if detected == False:
                        tags.append("to_{}".format(av))
            artifacts.append(self.build_artifact("file", self.obs_path, tags=tags))
        return artifacts

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "VT"
        predicate = "GetReport"
        value = "0"

        if self.service == "scan":
            predicate = "Scan"
        elif self.service == "rescan":
            predicate = "Rescan"
        elif self.service == "download":
            return {"taxonomies": taxonomies}

        result = {"has_result": True}

        if raw["response_code"] != 1:
            result["has_result"] = False

        result["positives"] = raw.get("positives", 0)
        result["total"] = raw.get("total", 0)

        if "scan_date" in raw:
            result["scan_date"] = raw["scan_date"]

        if self.service == "get":
            if "scans" in raw:
                result["scans"] = len(raw["scans"])
                value = "{}/{}".format(result["positives"], result["total"])
                if result["positives"] == 0:
                    level = "safe"
                elif result["positives"] < 5:
                    level = "suspicious"
                else:
                    level = "malicious"

            if "resolutions" in raw:
                result["resolutions"] = len(raw["resolutions"])
                value = "{} resolution(s)".format(result["resolutions"])
                if result["resolutions"] == 0:
                    level = "safe"
                elif result["resolutions"] < 5:
                    level = "suspicious"
                else:
                    level = "malicious"

            if "detected_urls" in raw:
                result["detected_urls"] = len(raw["detected_urls"])
                value = "{} detected_url(s)".format(result["detected_urls"])
                if result["detected_urls"] == 0:
                    level = "safe"
                elif result["detected_urls"] < 5:
                    level = "suspicious"
                else:
                    level = "malicious"

            if "detected_downloaded_samples" in raw:
                result["detected_downloaded_samples"] = len(
                    raw["detected_downloaded_samples"]
                )

        if self.service in ["scan", "rescan"]:
            if "scans" in raw:
                result["scans"] = len(raw["scans"])
                value = "{}/{}".format(result["positives"], result["total"])
                if result["positives"] == 0:
                    level = "safe"
                elif result["positives"] < 5:
                    level = "suspicious"
                else:
                    level = "malicious"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        if self.highlighted_antivirus:
            for av in self.highlighted_antivirus:
                detected = raw.get("scans", {}).get(av, {}).get("detected", None)
                if detected == False:
                    taxonomies.append(
                        self.build_taxonomy("info", namespace, av, "Not detected!")
                    )

        return {"taxonomies": taxonomies}

    def run(self):
        if self.service == "scan":
            if self.data_type == "file":
                filename = self.get_param("filename", "noname.ext")
                filepath = self.get_param("file", None, "File is missing")
                self.read_scan_response(
                    self.vt.scan_file(filepath, from_disk=True, filename=filename),
                    self.wait_file_report,
                )
            elif self.data_type == "url":
                data = self.get_param("data", None, "Data is missing")
                self.read_scan_response(self.vt.scan_url(data), self.wait_url_report)
            else:
                self.error("Invalid data type")

        elif self.service == "rescan":
            if self.data_type == "hash":
                data = self.get_param("data", None, "Data is missing")
                self.read_scan_response(
                    self.vt.rescan_file(data), self.wait_file_report
                )
            else:
                self.error("Invalid data type")

        elif self.service == "download":
            if self.data_type == "hash":
                data = self.get_param("data", None, "Data is missing")
                self.get_file(data)
                self.report({"message": "file downloaded"})

        elif self.service == "get":
            if self.data_type == "domain":
                data = self.get_param("data", None, "Data is missing")
                results = self.check_response(self.vt.get_domain_report(data))

            elif self.data_type == "fqdn":
                data = self.get_param("data", None, "Data is missing")
                results = self.check_response(self.vt.get_domain_report(data))

            elif self.data_type == "ip":
                data = self.get_param("data", None, "Data is missing")
                results = self.check_response(self.vt.get_ip_report(data))

            elif self.data_type == "file":
                hashes = self.get_param("attachment.hashes", None)
                if hashes is None:
                    filepath = self.get_param("file", None, "File is missing")
                    hash = hashlib.sha256(open(filepath, "rb").read()).hexdigest()
                else:
                    hash = next(h for h in hashes if len(h) == 64)
                results = self.check_response(self.vt.get_file_report(hash))

            elif self.data_type == "hash":
                data = self.get_param("data", None, "Data is missing")
                results = self.check_response(self.vt.get_file_report(data))

            elif self.data_type == "url":
                data = self.get_param("data", None, "Data is missing")
                results = self.check_response(self.vt.get_url_report(data))
            else:
                self.error("Invalid data type")

            # if aged and enabled rescan
            if self.data_type == "hash" and self.rescan_hash_older_than_days:
                if (
                    datetime.strptime(results["scan_date"], "%Y-%m-%d %H:%M:%S")
                    - datetime.now()
                ).days > self.rescan_hash_older_than_days:
                    self.read_scan_response(
                        self.vt.rescan_file(data), self.wait_file_report
                    )

            # download if hash, dangerous and not seen by av
            if (
                self.data_type == "hash"
                and (results.get("response_code", None) == 1)
                and (results.get("positives", 0) >= 5)
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
            self.report(results)

        else:
            self.error("Invalid service")


if __name__ == "__main__":
    VirusTotalAnalyzer().run()
