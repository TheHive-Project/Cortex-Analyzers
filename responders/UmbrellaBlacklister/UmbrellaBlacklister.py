#!/usr/bin/env python
# encoding: utf-8

from cortexutils.responder import Responder
import requests
from datetime import datetime

class UmbrellaBlacklister(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.integration_url = self.get_param('config.integration_url', None, "Integration URL Missing")

    def run(self):
        Responder.run(self)

        if self.data_type == 'thehive:case_artifact':

            domain = self.get_param('data.data', None, 'No artifacts available')

            dstUrl = "http://" + domain
            date = datetime.now().strftime("%Y-%m-%dT%XZ")

            headers = {
                'user-agent': 'UmbrellaBlacklister-Cortex-Responder',
                'Content-Type': 'application/json'
            }

            payload = {
                "alertTime": date,
                "deviceId": "cortex_thehive",
                "deviceVersion": "2.4.81",
                "dstDomain": domain,
                "dstUrl": dstUrl,
                "eventTime": date,
                "protocolVersion": "1.0a",
                "providerName": "Security Platform"
            }

            r = requests.post(self.integration_url, json=payload, headers=headers)
            if r.status_code == 200 | 202:
                self.report({'message': 'Blacklisted in Umbrella.'})
            else:
                self.error({'Failed to add to blacklist.'})

if __name__ == '__main__':
        UmbrellaBlacklister().run()
