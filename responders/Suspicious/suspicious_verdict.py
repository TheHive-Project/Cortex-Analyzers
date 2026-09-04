#!/usr/bin/env python3
# Author: THA-CERT // EBA

import requests
import re
from cortexutils.responder import Responder

class Suspicious_Verdict(Responder):
    def __init__(self):
        Responder.__init__(self)

        self.suspicious_url = self.get_param("config.suspicious_url", "http://localhost:9020")
        self.suspicious_token = self.get_param("config.suspicious_token", "Missing Suspicious API Key")

        self.thehive_id = self.get_param("data.id")
        self.thehive_tags = self.get_param("data.tags", [])
        self.thehive_title = self.get_param("data.title", "")
        self.thehive_type = self.get_param("data._type", "case").lower()

    def run(self):
        Responder.run(self)

        if not self.thehive_id:
            self.error(f"Unable to find the {self.thehive_type.capitalize()} ID in the payload.")

        suspicious_case_id = re.search(r"#(\d+)(?=\s-)", self.thehive_title)

        if suspicious_case_id:
            suspicious_case_id = suspicious_case_id.group(1)
        else:
            self.error(f"Unable to find the Suspicious Case ID in the {self.thehive_type} title.")
            
        if not self.thehive_tags:
            self.error(f"No tags attached to the TheHive {self.thehive_type} : {self.thehive_id} .")
            
        verdicts = [tag for tag in self.thehive_tags if tag.startswith('suspicious:verdict=')]

        if len(verdicts) > 1:
            self.error(f"There are multiple verdict tags on this {self.thehive_type}! Please keep only one : {verdicts}")

        if 'suspicious:verdict="DANGEROUS"' in self.thehive_tags:
            suspicious_verdict = "DANGEROUS"
            self.request(suspicious_case_id, suspicious_verdict)

        elif 'suspicious:verdict="SAFE"' in self.thehive_tags:
            suspicious_verdict = "SAFE"
            self.request(suspicious_case_id, suspicious_verdict)

        elif 'suspicious:verdict="SUSPICIOUS"' in self.thehive_tags:
            suspicious_verdict = "SUSPICIOUS"
            self.request(suspicious_case_id, suspicious_verdict)

        else:
            self.error(f"No valid Suspicious verdict tag found in the Thehive {self.thehive_type} : {self.thehive_id} .")

    def request(self, suspicious_case_id, suspicious_verdict):
        url = f"{self.suspicious_url}/api/investigations/{suspicious_case_id}/edit-global/"

        headers = {
            "accept": "application/json",
            "Authorization": f"Token {self.suspicious_token}"
        }

        payload = {
            "score": 10,
            "confidence": 100,
            "classification": f"{suspicious_verdict}"
        }

        try:
            response = requests.patch(
                url,
                headers=headers,
                json=payload,
                verify=False
            )

            if response.status_code == 200:
                self.report(
                    {"message": f"Suspicious Case : {suspicious_case_id} has been classified as {suspicious_verdict}."})
            else:
                self.error(f"Error : {response.text}")

        except requests.exceptions.RequestException as e:
            self.error(f"Error during the request : {str(e)}")

    def operations(self, raw):
        new_tag = 'suspicious:status="challenge_reviewed."'

        if self.thehive_type == "alert":
            return [
                self.build_operation("AddTagToAlert", tag=new_tag)
            ]
        else:
            return [
                self.build_operation("AddTagToCase", tag=new_tag)
            ]

if __name__ == '__main__':
    Suspicious_Verdict().run()
