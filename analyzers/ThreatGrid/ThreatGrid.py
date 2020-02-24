#!/usr/bin/env python3
# encoding: utf-8

import requests

from time import sleep
from cortexutils.analyzer import Analyzer
from simplejson.errors import JSONDecodeError


class ThreatGridAnalyzer(Analyzer):
    """
    Threat Grid analyzer submits a 'file' or 'url' to Threat Grid for dynamic analysis and returns
    the results. Queryies for a 'hash' and returns the analysis results from the sample with the
    highest threat score submitted within the last 90 days.
    """

    def __init__(self):
        Analyzer.__init__(self)
        self.tg_host = self.get_param(
            "config.tg_host", None, "No Threat Grid host given."
        )
        self.api_key = self.get_param(
            "config.api_key", None, "No Threat Grid API Key given."
        )

        # Create a Requests Session
        self.base_url = "https://{}/api/v2".format(self.tg_host)
        self.tg_session = requests.Session()
        auth_param = {"api_key": self.api_key}
        self.tg_session.params.update(auth_param)

    def verify_response(self, response, key):
        """Verify the HTTP status code is 200 and the expected key is present in the JSON
        """
        try:
            return bool(response.status_code == 200 and key in response.json())
        except JSONDecodeError:
            self.error(
                "The server responded with HTTP status code 200 but did not return JSON"
            )

    def wait_for_completion(self, sample_id):
        """Check for sample completion every minute for 10 minutes
        """
        url = self.base_url + "/samples/{}/state".format(sample_id)
        finished = False
        tries = 0
        while not finished and tries <= 20:  # wait max 10 min check every 30 seconds
            if tries == 0:
                sleep(3)  # It takes a second for the respnse to be available
            else:
                sleep(30)
            response = self.tg_session.get(url)
            state = response.json().get("data", {}).get("state")
            if state == "succ":
                finished = True
            elif state == "fail":
                self.get_fail_status(sample_id)
            tries += 1
        if not finished:
            self.error(
                "Timed out waiting for Sample analysis. Sample ID: {}".format(sample_id)
            )

    def get_fail_status(self, sample_id):
        """When a sample fails get the reason for the failure
        """
        url = self.base_url + "/samples/{}".format(sample_id)
        response = self.tg_session.get(url)

        if self.verify_response(response, "data"):
            status = response.json().get("data", []).get("status")
            if status:
                self.error(
                    "Sample analysis failed with status. Sample ID: {} - {}".format(
                        sample_id, status
                    )
                )
            else:
                self.error("Sample analysis failed. Sample ID: {}".format(sample_id))
        else:
            self.error(
                "Sample analysis failed, error getting fail status. Sample ID: {} recieved {} - {}".format(
                    sample_id, response.status_code, response.text
                )
            )

    def get_sample_id(self, submit_response):
        """Verify response after submitting a sample and return the Sample ID
        """
        if self.verify_response(submit_response, "data"):
            sample_id = submit_response.json()["data"]["id"]
            return sample_id
        else:
            self.error(
                "Error submitting sample, recieved {} - {}".format(
                    submit_response.status_code, submit_response.text
                )
            )

    def get_sample_results(self, sample_id):
        """Collect the sample analysis results
        """
        # Get Analysis JSON from Threat Grid
        analysis_response = self.get_analysis_json(sample_id)

        # Get Sample Summary JSON from Threat Grid
        summary_response = self.get_summary(sample_id)

        # Build report from summary and analyis results
        self.build_repot(analysis_response, summary_response)

    def get_summary(self, sample_id):
        """Get the sample summary information
        """
        # Get Summary about sample from Threat Grid
        url = self.base_url + "/samples/{}/summary".format(sample_id)
        response = self.tg_session.get(url)

        if self.verify_response(response, "data"):
            return response
        else:
            self.error(
                "Fetching sample summary failed. Sample ID: {} recieved {} - {}".format(
                    sample_id, response.status_code, response.text
                )
            )

    def get_analysis_json(self, sample_id):
        """Get the sample analysis JSON
        """
        url = self.base_url + "/samples/{}/analysis.json".format(sample_id)
        response = self.tg_session.get(url)

        if self.verify_response(response, "metadata"):
            return response
        else:
            self.error(
                "Fetching analysis JSON failed. Sample ID: {} recieved {} - {}".format(
                    sample_id, response.status_code, response.text
                )
            )

    def build_repot(self, analysis_response, summary_response):
        """Reformat elements from the analysis JSON into a custom report structure
        """
        analysis_json = analysis_response.json()
        summary_json = summary_response.json()

        raw_report = {}
        raw_report["host"] = self.tg_host
        raw_report["summary"] = summary_json.get("data")
        raw_report["summary"]["domains"] = len(analysis_json.get("domains"))
        raw_report["metadata"] = analysis_json.get("metadata")
        raw_report["threat"] = analysis_json.get("threat")
        raw_report["status"] = analysis_json.get("status")
        raw_report["iocs"] = analysis_json.get("iocs")
        raw_report["network"] = analysis_json.get("network")
        raw_report["domains"] = analysis_json.get("domains")

        self.report(raw_report)

    def run(self):

        dataType = self.get_param("dataType")

        if dataType == "file":
            file = self.get_param("file")
            filename = self.get_param("filename")

            parameters = {"private": "true", "sample_filename": filename}

            # Read file and submit to Threat Grid
            with open(file, "rb") as sample:
                submit_response = self.tg_session.post(
                    self.base_url + "/samples",
                    files={"sample": sample},
                    params=parameters,
                )

            # Verify response and store Sample ID
            sample_id = self.get_sample_id(submit_response)

            # Wait for analysis completion
            self.wait_for_completion(sample_id)

            # Get analysis results
            self.get_sample_results(sample_id)

        elif dataType == "url":
            observable_url = self.get_param("data")

            parameters = {"private": "true", "url": observable_url}

            # Submit to Threat Grid
            submit_response = self.tg_session.post(
                self.base_url + "/samples", params=parameters
            )

            # Verify response and store Sample ID
            sample_id = self.get_sample_id(submit_response)

            # Wait for analysis completion
            self.wait_for_completion(sample_id)

            # Get analysis results
            self.get_sample_results(sample_id)

        elif dataType == "hash":
            observable_hash = self.get_param("data")

            parameters = {
                "limit": 1,
                "state": "succ",
                "term": "sample",
                "sort_by": "threat",
                "sort_order": "desc",
                "after": "90 days ago",
                "q": observable_hash,
            }

            query_response = self.tg_session.get(
                self.base_url + "/search/submissions", params=parameters
            )

            # Verify response and store Sample ID
            if self.verify_response(query_response, "data"):
                query_response_json = query_response.json()
                current_item_count = query_response_json["data"]["current_item_count"]
                if current_item_count > 0:
                    sample_id = query_response_json["data"]["items"][0]["item"][
                        "sample"
                    ]
                else:
                    self.error("No samples found in the last 90 days")
            else:
                self.error(
                    "Error submitting file, recieved {} - {}".format(
                        query_response.status_code, query_response.text
                    )
                )

            # Get analysis results
            self.get_sample_results(sample_id)

        else:
            self.error("Data type currently not supported")

    def summary(self, raw):
        taxonomies = []
        namespace = "TG"
        predicate = "Analysis"

        threat = raw.get("threat", {})
        threat_score = threat.get("threat_score")

        # Set level based on Threat Score
        if threat_score >= 90:
            level = "malicious"
        elif 90 > threat_score >= 50:
            level = "suspicious"
        elif threat_score < 50:
            level = "safe"

        taxonomies.append(
            self.build_taxonomy(level, namespace, predicate, value=threat_score)
        )
        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    ThreatGridAnalyzer().run()
