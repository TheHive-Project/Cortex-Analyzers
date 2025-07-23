#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
import requests


class PaloAltoWildfire(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.scheme = "https"
        self.api_key = self.get_param(
            'config.api_key', None, "API-key Missing")
        self.wildfire_url = self.get_param(
            'config.wildfire_url', None, "Wildfire URL Missing")
        self.observable_type = self.get_param('data.dataType', None, "Data type is empty")
        self.observable_description = self.get_param('data.message', None, "Description is empty")

    def run(self):
        Responder.run(self)
        try:
            supported_observables = ["domain", "url", "fqdn"]
            if self.observable_type in supported_observables:
                if self.observable_type == "domain" or self.observable_type == "fqdn":
                    domain = self.get_param('data.data', None, 'No artifacts available')
                    observable = "{}://{}".format(self.scheme, domain)
                elif self.observable_type == "url":
                    observable = self.get_param('data.data')

                headers = {
                    'User-Agent': 'PaloAltoWildfire-Cortex-Responder'
                }
                payload = {
                    'apikey': (None, self.api_key),
                    'link': (None, observable),
                }
                response = requests.post(self.wildfire_url, files=payload, headers=headers)
                if response.status_code == 200:
                    self.report({'message': 'Observable sent to Wildfire. Message: {}'.format(response.text)})
                elif response.status_code == 401:
                    self.error({'message': 'Failed authentication. Check API-Key. Message: {}'.format(response.text)})
                else:
                    self.error('Failed to submit request. Error code: {}. Error message: {}'
                               .format(response.status_code, response.text))
            else:
                self.error('Incorrect dataType. "Domain", "FQDN", or "URL" expected.')

        except requests.exceptions.RequestException as e:
            self.error(str(e))

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='Wildfire:submit')]


if __name__ == '__main__':
    PaloAltoWildfire().run()
