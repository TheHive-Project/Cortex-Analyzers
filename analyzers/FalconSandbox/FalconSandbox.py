#!/usr/bin/env python3
# encoding: utf-8


import hashlib
import json
import time
import traceback

from cortexutils.analyzer import Analyzer
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session


class FalconSandbox(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.Client_ID = self.get_param(
            'config.Client_ID', None, "Falcon ClientID missing")
        self.Client_Secret = self.get_param(
            'config.Client_Secret', None, "Falcon Client_Secret missing")
        self.API_Base_Url = self.get_param(
            'config.API_Base_Url', None, "Falcon API Base URl missing")
        self.client = BackendApplicationClient(client_id=self.Client_ID)
        self.oauth = OAuth2Session(client=self.client)
        self.token = self.oauth.fetch_token(token_url=self.API_Base_Url + "/oauth2/token", client_id=self.Client_ID, client_secret=self.Client_Secret)

    def summary(self, raw):
        taxonomies = []
        namespace = "CS-Sandbox"
        predicate = "Threat-Score"
        value = str(raw['resources'][0]['sandbox'][0]['threat_score'])
        level = str(
            raw['resources'][0]['sandbox'][0]['verdict'])  # no verdict, No Specific Threat, suspicious, malicious

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def calc_sha256_hash(self, filepath):
        buf_size = 65536  # lets read stuff in 64kb chunks!
        l_sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while True:
                l_data = f.read(buf_size)
                if not l_data:
                    break
                l_sha256.update(l_data)

        l_own_sha256 = l_sha256.hexdigest()
        return l_own_sha256

    def rest_api_request(self, method, url, headers, data):
        # get the get, post or delete method from the OAuth2Session object
        method_to_call = getattr(self.oauth, method)

        response = method_to_call(url, data=data, headers=headers)
        l_json_response = json.loads(response.text)

        if l_json_response["errors"] and l_json_response["errors"][0]["code"] == 403:
            # ok, we need a new token
            self.client = BackendApplicationClient(client_id=self.Client_ID)
            self.oauth = OAuth2Session(client=self.client)
            self.token = self.oauth.fetch_token(token_url=self.API_Base_Url + "/oauth2/token",
                                                client_id=self.Client_ID, client_secret=self.Client_Secret)
            # lets do it again with new token
            response = method_to_call(url, data=data, headers=headers)
            l_json_response = json.loads(response.text)

        return l_json_response

    def run(self):
        try:
            Analyzer.run(self)

            filename = self.get_param("filename", "")
            filepath = self.get_param("file", "")

            l_file_hash_sha256 = self.calc_sha256_hash(filepath)

            # get the latest report for file with sha256
            url = self.API_Base_Url + \
                  "/falconx/queries/submissions/v1?filter=sandbox.sha256:\"" + \
                  l_file_hash_sha256 + \
                  "\"&limit=1"
            payload = {}
            headers = {'Content-Type': 'application/json'}
            json_response = self.rest_api_request(method="get", url=url, headers=headers, data=payload)

            if json_response["errors"]:
                self.error(str(json_response["errors"]))
                return
            else:
                if not json_response["resources"]:
                    # no scan reports exists for this file -> submit the file for analysis
                    payload = open(filepath, "rb")
                    headers = {'Content-Type': 'application/octet-stream'}
                    url = self.API_Base_Url + \
                          "/samples/entities/samples/v2?file_name=" + \
                          filename + \
                          "&comment=" + \
                          "added by TheHive:FalconSandbox-Analyzer"
                    json_response_submit = self.rest_api_request(method="post", url=url, data=payload, headers=headers)
                    if json_response_submit["errors"]:
                        self.error(str(json_response_submit["errors"]))
                        return
                    else:
                        # start the analysis of the submitted file
                        url = self.API_Base_Url + \
                              "/falconx/entities/submissions/v1"
                        headers = {'Content-Type': 'application/json'}
                        payload = "{\"sandbox\": " \
                                  "[{\"sha256\": \"" + \
                                  l_file_hash_sha256 + \
                                  "\",\"environment_id\": 110 }] }"
                        json_response_start_analysis = self.rest_api_request(method="post", url=url, data=payload,
                                                                             headers=headers)
                        if json_response_start_analysis["errors"]:
                            self.error(str(json_response_start_analysis["errors"]))
                            return
                        else:
                            # now the file is submitted and analysis is started, let's get the report_id now
                            url = self.API_Base_Url + \
                                  "/falconx/queries/submissions/v1?filter=sandbox.sha256:\"" \
                                  + l_file_hash_sha256 + \
                                  "\"&limit=1"
                            payload = {}
                            headers = {'Content-Type': 'application/json'}
                            report_found = 0
                            while report_found == 0:
                                json_response = self.rest_api_request(method="get", url=url, data=payload,
                                                                      headers=headers)
                                if json_response["errors"]:
                                    self.error(str(json_response["errors"]))
                                    return
                                if not json_response["resources"]:
                                    # still waiting for the report ID
                                    time.sleep(60.0)
                                    report_found = 0
                                else:
                                    # report_id is found
                                    report_id = json_response["resources"][0]
                                    report_found = 1
                else:
                    report_id = json_response["resources"][0]

                analyzeinprogress = 1
                while analyzeinprogress == 1:
                    url = self.API_Base_Url + \
                          "/falconx/entities/report-summaries/v1?ids=" + report_id
                    payload = {}
                    headers = {'Content-Type': 'application/json'}
                    json_response_report = self.rest_api_request(method="get", url=url, data=payload, headers=headers)
                    if json_response_report["errors"]:
                        self.error(str(json_response_report["errors"]))
                        return

                    if not json_response_report["resources"] and \
                            json_response_report["meta"]["quota"]["in_progress"] != 0:
                        # still waiting for the analysis results
                        time.sleep(60.0)
                        analyzeinprogress = 1
                    else:
                        # report is ready
                        analyzeinprogress = 0

                if json_response_report["errors"]:
                    self.error(str(json_response_report["errors"]))
                    return
                else:
                    self.report(json_response_report)

        except Exception as ex:
            self.error(traceback.format_exc())


if __name__ == '__main__':
    FalconSandbox().run()
