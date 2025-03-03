#!/usr/bin/env python3
# encoding: utf-8
import time
import requests
from os.path import basename
from cortexutils.analyzer import Analyzer
from requests.packages.urllib3.exceptions import InsecureRequestWarning


class AnyRunAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.url = "https://api.any.run/v1"
        self.token = self.get_param("config.token", None, "Service token is missing")
        self.privacy_type = self.get_param("config.privacy_type", None, "Privacy type is missing")
        self.verify_ssl = self.get_param("config.verify_ssl", True, None)
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.env_bitness = self.get_param("config.env_bitness", None, None)
        self.env_version = self.get_param("config.env_version", None, None)
        self.env_type = self.get_param("config.env_type", None, None)
        self.opt_network_connect = self.get_param("config.opt_network_connect", None, None)
        self.opt_network_fakenet = self.get_param("config.opt_network_fakenet", None, None)
        self.opt_network_tor = self.get_param("config.opt_network_tor", None, None)
        self.opt_network_mitm = self.get_param("config.opt_network_mitm", None, None)
        self.opt_network_geo = self.get_param("config.opt_network_geo", None, None)
        self.opt_kernel_heavyevasion = self.get_param("config.opt_kernel_heavyevasion", None, None)
        self.opt_timeout = self.get_param("config.opt_timeout", None, None)
        self.obj_ext_startfolder = self.get_param("config.obj_ext_startfolder", None, None)
        self.obj_ext_browser = self.get_param("config.obj_ext_browser", None, None)

    def summary(self, raw):
        taxonomies = []
        level = "safe"
        namespace = "AnyRun"
        predicate = "Sandbox"
        value = (
            raw.get("analysis", {}).get("scores", {}).get("verdict", {}).get("score", 0)
        )
        if 50 < value < 100:
            level = "suspicious"
        elif value == 100:
            level = "malicious"

        taxonomies.append(
            self.build_taxonomy(level, namespace, predicate, "{0}/100".format(value))
        )

        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        try:
            headers = {"Authorization": "API-Key {0}".format(self.token)}

            status_code = None
            tries = 0
            if self.data_type == "file":
                filepath = self.get_param("file", None, "File is missing")
                filename = self.get_param("filename", basename(filepath))
                while status_code in (None, 429) and tries <= 15:
                    with open(filepath, "rb") as sample:
                        files = {"file": (filename, sample)}
                        data = {"opt_privacy_type": self.privacy_type,
                                "env_bitness": self.env_bitness,
                                "env_version": self.env_version,
                                "env_type": self.env_type,
                                "opt_network_connect": self.opt_network_connect,
                                "opt_network_fakenet": self.opt_network_fakenet,
                                "opt_network_tor": self.opt_network_tor,
                                "opt_network_mitm": self.opt_network_mitm,
                                "opt_network_geo": self.opt_network_geo,
                                "opt_kernel_heavyevasion": self.opt_kernel_heavyevasion,
                                "opt_timeout": self.opt_timeout,
                                "obj_ext_startfolder": self.obj_ext_startfolder }
                        response = requests.post(
                            "{0}/analysis".format(self.url),
                            files=files,
                            data=data,
                            headers=headers,
                            verify=self.verify_ssl,
                        )
                    status_code = response.status_code
                    if status_code == 200:
                        task_id = response.json()["data"]["taskid"]
                    elif status_code == 201:
                        task_id = response.json()["data"]["taskid"]
                    elif status_code == 429:
                        # it not support parallel runs, so we wait and resubmit later
                        time.sleep(60)
                        tries += 1
                    else:
                        self.error(response.json()["message"])
            elif self.data_type == "url":
                url = self.get_param("data", None, "Url is missing")
                data = {"obj_type": "url", 
                        "obj_url": url, 
                        "opt_privacy_type": self.privacy_type,
                        "env_bitness": self.env_bitness,
                        "env_version": self.env_version,
                        "env_type": self.env_type,
                        "opt_network_connect": self.opt_network_connect,
                        "opt_network_fakenet": self.opt_network_fakenet,
                        "opt_network_tor": self.opt_network_tor,
                        "opt_network_mitm": self.opt_network_mitm,
                        "opt_network_geo": self.opt_network_geo,
                        "opt_kernel_heavyevasion": self.opt_kernel_heavyevasion,
                        "opt_timeout": self.opt_timeout,
                        "obj_ext_browser": self.obj_ext_browser }
                while status_code in (None, 429) and tries <= 15:
                    response = requests.post(
                        "{0}/analysis".format(self.url),
                        data=data,
                        headers=headers,
                        verify=self.verify_ssl,
                    )
                    status_code = response.status_code
                    if status_code == 200:
                        task_id = response.json()["data"]["taskid"]
                    elif status_code == 201:
                        task_id = response.json()["data"]["taskid"]
                    elif status_code == 429:
                        # it not support parallel runs, so we wait and resubmit later
                        time.sleep(60)
                        tries += 1
                    else:
                        self.error(response.json()["message"])
            else:
                self.error("Invalid data type!")

            finished = False
            tries = 0
            while not finished and tries <= 15:  # wait max 15 mins
                time.sleep(60)
                response = requests.get(
                    "{0}/analysis/{1}".format(self.url, task_id),
                    headers=headers,
                    verify=self.verify_ssl,
                )
                if response.status_code == 200:
                    finished = (
                        True if response.json()["data"]["status"] == "done" else False
                    )
                elif 400 < response.status_code < 500:
                    self.error(response.json()["message"])
                tries += 1
            if not finished:
                self.error("AnyRun analysis timed out")

            # this items could be huge, we provide link to the report so avoid them in cortex
            final_report = response.json()["data"]
            final_report.pop("environments", None)
            final_report.pop("modified", None)
            for incident in final_report.get("incidents", []):
                incident.pop("events", None)
            for process in final_report.get("processes", []):
                process.pop("modules", None)   
            self.report(final_report)

        except requests.exceptions.RequestException as e:
            self.error(str(e))

        except Exception as e:
            self.unexpectedError(e)


if __name__ == "__main__":
    AnyRunAnalyzer().run()
