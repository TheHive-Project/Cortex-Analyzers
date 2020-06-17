#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer

import io
import requests
import time
import json
from jbxapi import JoeSandbox


class JoeSandboxAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.url = self.get_param("config.url", None, "JoeSandbox url is missing")
        if self.get_param("config.key"):
            apikey = self.get_param("config.key")
        else:
            apikey = self.get_param(
                "config.apikey", None, "JoeSandbox API key is missing"
            )
        self.service = self.get_param(
            "config.service", None, "JoeSandbox service is missing"
        )
        self.analysistimeout = self.get_param("config.analysistimeout", 30 * 60, None)
        self.networktimeout = self.get_param("config.networktimeout", 30, None)
        self.joe = JoeSandbox(apikey, self.url, verify_ssl=False, accept_tac=True)

    def summary(self, raw):
        taxonomies = []
        namespace = "JSB"
        predicate = "Report"

        r = raw["detection"]

        value = "{}/{}".format(r["score"], r["maxscore"])

        if r["clean"]:
            level = "safe"
        elif r["suspicious"]:
            level = "suspicious"
        elif r["malicious"]:
            level = "malicious"
        else:
            level = "info"
            value = "Unknown"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        # file analysis with internet access
        if self.service == "file_analysis_inet":
            filename = self.get_param("filename", "")
            filepath = self.get_param("file", "")
            response = self.joe.submit_sample((filename, open(filepath, "rb")))
        elif self.service == "file_analysis_noinet":
            filename = self.get_param("filename", "")
            filepath = self.get_param("file", "")
            response = self.joe.submit_sample(
                (filename, open(filepath, "rb")), params={"internet-access": False}
            )
        # url analysis
        elif self.service == "url_analysis":
            response = self.joe.submit_url(self.get_data())

        else:
            self.error("Unknown JoeSandbox service")

        # Submit the file/url for analysis
        submission_id = response["submission_id"]

        # Wait for the analysis to finish
        finished = False
        tries = 0
        while not finished and tries <= self.analysistimeout / 60:
            time.sleep(60)
            response = self.joe.submission_info(submission_id)
            webid = response["analyses"][0]["webid"]
            if response["status"] == "finished":
                finished = True
            tries += 1
        if not finished:
            self.error("JoeSandbox analysis timed out")
        # Download the report
        response = self.joe.analysis_download(webid, "irjsonfixed", run=0)
        analysis = json.loads(response[1].decode("utf-8")).get("analysis", None)
        if analysis:
            analysis["htmlreport"] = (
                self.url + "analysis/" + str(analysis["id"]) + "/0/html"
            )
            analysis["pdfreport"] = (
                self.url + "analysis/" + str(analysis["id"]) + "/0/pdf"
            )
            self.report(analysis)
        else:
            self.error("Invalid output")


if __name__ == "__main__":
    JoeSandboxAnalyzer().run()
