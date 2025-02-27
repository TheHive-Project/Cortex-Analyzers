#!/usr/bin/env python3
# encoding: utf-8
import json
import requests
from base64 import b64encode
from cortexutils.analyzer import Analyzer

class UmbrellaAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.api_key = self.get_param('config.api_key', None, 'api_key is missing')
        self.api_secret = self.get_param('config.api_secret', None, 'api_secret is missing')
        self.organization_id = self.get_param('config.organization_id', None, 'organization_id is missing')
        self.query_limit = str(self.get_param('config.query_limit', 20))
        self.token = None

    def umbrella_runreport(self, destination):
        token = self.get_bearer_token()
        headers = {
             'Authorization': f'Bearer {self.token}',
             'Content-Type': 'application/json'
        }

        report_url = f"https://reports.api.umbrella.com/v2/organizations/{self.organization_id}/activity?from=-7days&to=now&domains={destination}&limit={self.query_limit}"

        response = requests.get(report_url, headers=headers)
        print(response)
        if response.status_code == 200:
            return json.loads(response.text)
        else:
            print(f"Failed to get categories: {response.text}")
            return None

    def get_bearer_token(self):
        auth_url = "https://api.umbrella.com/auth/v2/token"
        credentials = f"{self.api_key}:{self.api_secret}"
        encoded_credentials = b64encode(credentials.encode()).decode()

        headers = {
            'Authorization': f'Basic {encoded_credentials}',
            'Content-Type': 'application/json'
        }

        response = requests.post(auth_url, headers=headers)
        if response.status_code == 200:
            token_data = response.json()
            self.token = token_data['access_token']
            #print(self.token)
            return self.token
        else:
            print(f"Failed to get bearer token: {response.text}")
            return None

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Umbrella"
        predicate = "GetReport"
        value = "0"

        if "data" in raw and len(raw["data"]) > 0:
            item = raw["data"][0]
            if "verdict" in item:
                verdicts = item['verdict']
                value = "{}".format(verdicts)

                if verdicts.lower() in ["allowed", "passed", "none"]:
                    level = "safe"
                elif verdicts.lower() in ["blocked", "rejected", "failed"]:
                    level = "malicious"
                else:
                    level = "suspicious"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {'taxonomies': taxonomies}



    def run(self):
        # Map The Hive observable types to Umbrella observable types
        observable_mapping = {
            "domain": "domain",
            "fqdn": "domain",
        }


        if self.service == 'get':
            dataType = self.get_param("dataType")

            # Validate the supplied observable type is supported
            if dataType in observable_mapping.keys():
                data = self.get_param('data', None, 'Data is missing')
                r = self.umbrella_runreport(data)
                self.report(r)
            else:
                self.error('Invalid data type')
        else:
            self.error('Invalid service type')

if __name__ == '__main__':
        UmbrellaAnalyzer().run()
