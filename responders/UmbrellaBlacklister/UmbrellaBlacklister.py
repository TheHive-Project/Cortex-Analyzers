#!/usr/bin/env python
# encoding: utf-8

from cortexutils.responder import Responder
import requests


class UmbrellaBlacklister(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.integration_url = self.get_param('config.integration_url', None, "Integration URL Missing")

    def run(self):
        Responder.run(self)

        if self.data_type == 'domain':

            domain = self.get_data()
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

            try:
                r = requests.post(self.integration_url, json=payload, headers=headers)
                if r.status_code == 200 | 202:
                    self.report({'message': 'Blacklisted in Umbrella.'})
                else:
                    self.report({'message': 'Failed to add to blacklist.'})
                except Exception as e:
                    self.unexpectedError(e)

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='umbrella:blacklisted')]


if __name__ == '__main__':
UmbrellaBlacklister().run()
