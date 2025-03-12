#!/usr/bin/env python3

import requests
from typing import Dict, Any
from cortexutils.responder import Responder

requests.packages.urllib3.disable_warnings()


class BinalyzeAIR(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.air_console_url = self.get_param(
            "air_console_url", None, "Binalyze AIR console URL is missing!"
        )
        self.air_api_key = self.get_param(
            "air_api_key", None, "Binalyze AIR API key is missing!"
        )
        self.proxies = self.get_param("config.proxy", None)

        self.headers: Dict[str, Any] = {
            'Authorization': f'Bearer {self.air_api_key}',
            'User-Agent': 'Binalyze AIR',
            'Content-type': 'application/json',
            'Accept-Charset': 'UTF-8'
        }
        self.service = self.get_param("config.service", None, "Service Missing!")
        self.hostname = self.get_param('hostname', '', None, 'Hostname is Missing!')
        self.organization_id = self.get_param('organization_id', 0)

        if self.service == 'acquire':
            self.profile = self.get_param('profile', '')
            self.case_id = self.get_param('case_id', '')
        if self.service == 'isolation':
            self.hostname = self.get_param('hostname', '')
            self.isolation = self.get_param('isolation', '')

    def run(self):
        Responder.run(self)
        if self.service == "acquire":
            if self.hostname is None:
                self.error(f'{self.hostname} is Empty!')
                return
            if self.profile is None:
                self.error(f'{self.profile} is Empty!')
                return
            if self.profile:
                try:
                    profile = requests.get(
                        f'https://{self.air_console_url}/api/public/acquisitions/profiles?filter[name]={self.profile}&filter[organizationIds]=0',
                        headers=self.headers, verify=False).json()['result']['entities'][0]['_id']
                    self.profile = profile
                except Exception as ex:
                    self.error(f'{self.profile} is wrong!')
                return
            if self.case_id is None:
                self.error(f'{self.case_id} is Empty!')
                return
            if self.organization_id is None:
                self.error(f'{self.organization_id} is Empty!')
                return

            payload: Dict[str, Any] = {
                "caseId": self.case_id,
                "droneConfig": {
                    "autoPilot": False,
                    "enabled": False
                },
                "taskConfig": {
                    "choice": "use-policy"
                },
                "acquisitionProfileId": self.profile,
                "filter": {
                    "name": self.hostname,
                    "organizationIds": [self.organization_id]
                }
            }
            response = requests.post(
                f'{self.air_console_url}/api/public/acquisitions/acquire',
                headers=self.headers,
                json_data=payload
            )
            if response.status_code == requests.codes.ok:
                self.report({'message': f'Acquisition task has been started in {self.hostname}'})
            else:
                self.error(
                    f'Error, unable to start acquisition task. I received {response.status_code} status code from Binalyze AIR!'
                )

        if self.service == "isolate":
            if self.hostname is None:
                self.error(f'{self.hostname} is Empty!')
                return
            if self.isolation is None:
                self.error(f'{self.isolation} is Empty!')
                return
            if self.organization_id is None:
                self.error(f'{self.organization_id} is Empty!')
                return
            if self.isolation is True:
                payload: Dict[str, Any] = {
                    "enabled": True,
                    "filter": {
                        "name": self.hostname,
                        "organizationIds": [self.organization_id]
                    }
                }
                return
            if self.isolation is False:
                payload: Dict[str, Any] = {
                    "enabled": False,
                    "filter": {
                        "name": self.hostname,
                        "organizationIds": [self.organization_id]
                    }
                }
                return

            response = requests.post(
                f'{self.air_console_url}/api/public/endpoints/tasks/isolation',
                headers=self.headers,
                json_data=payload
            )
            if response.status_code == requests.codes.ok:
                self.report({'message': f'Isolation task has been started in {self.hostname}'})
            else:
                self.error(
                    f'Error, unable to start isolation task. I received {response.status_code} status code from Binalyze AIR!'
                )

    def operations(self, raw):
        return [self.build_operation("AddTagToArtifact", tag=f"BinalyzeAIR:{self.service}d the endpoint.")]


if __name__ == "__main__":
    BinalyzeAIR().run()