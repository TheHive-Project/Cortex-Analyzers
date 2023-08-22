#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
import requests
from datetime import datetime


class UmbrellaBlacklister(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.integration_url = self.get_param(
            'config.integration_url', None, "Integration URL Missing")

    def run(self):
        Responder.run(self)

        data_type = self.get_param('data.dataType')
        ioc_types = ["domain", "url", "fqdn"]
        if data_type in ioc_types:

            if data_type == "domain" or data_type == "fqdn":
                domain = self.get_param(
                    'data.data', None, 'No artifacts available')

                dstUrl = "http://" + domain

            elif data_type == "url":
                dstUrl = self.get_param(
                    'data.data', None, 'No artifacts available')

                domain = dstUrl.split('/')[2]

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

            r = requests.post(self.integration_url,
                              json=payload, headers=headers)
            if r.status_code == 200 | 202:
                self.report({'message': 'Blacklisted in Umbrella.'})
            else:
                self.error('Failed to add to blacklist.')
        else:
            self.error('Incorrect dataType. "Domain", "FQDN", or "URL" expected.')

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='Umbrella:blocked')]


if __name__ == '__main__':
    UmbrellaBlacklister().run()
