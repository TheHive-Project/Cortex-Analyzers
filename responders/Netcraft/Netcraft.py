#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
import requests


class NetcraftReporter(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.scheme = "https"
        self.api_key = self.get_param(
            'config.api_key', None, "API-key Missing")
        self.takedown_url = self.get_param(
            'config.takedown_url', None, "Takedown URL Missing")
        self.observable_type = self.get_param('data.dataType', None, "Data type is empty")
        self.observable_description = self.get_param('data.message', None, "Description is empty")
        self.username = self.get_param(
            'config.username', None, "Takedown Username is empty")
        self.password = self.get_param(
            'config.password', None, "Takedown Password is empty")
        self.useUserPass = self.get_param(
            'config.useUserPass', None, "Takedown Use Username Password authentication is empty")

    def run(self):
        Responder.run(self)
        try:
            supported_observables = ["domain", "url", "fqdn"]
            if self.observable_type in supported_observables:
                if self.observable_type == "domain" or self.observable_type == "fqdn":
                    domain = self.get_param('data.data', None, 'No artifacts available')
                    takedown = "{}://{}".format(self.scheme, domain)
                elif self.observable_type == "url":
                    takedown = self.get_param('data.data')

                session = requests.Session()
                session.headers.update({'User-Agent': 'Netcraft-Cortex-Responder'})

                if self.useUserPass:
                    session.auth = (self.username, self.password)
                else:
                    session.headers.update({'Authorization': 'Bearer ' + self.api_key})

                payload = {
                    "attack": takedown,
                    "comment": "Automated takedown via Cortex"
                }
                response = session.post(self.takedown_url, data=payload)

                if response.status_code == 200:
                    self.report({'message': 'Takedown request sent to Netcraft. Message: {}'.format(response.text)})
                elif response.status_code == 401:
                    self.error('Failed authentication. Check API-Key. Message: {}'.format(response.text))
                else:
                    self.error('Failed to submit takedown request. Error code: {}. Error message: {}'
                               .format(response.status_code, response.text))
            else:
                self.error('Incorrect dataType. "Domain", "FQDN", or "URL" expected.')

        except requests.exceptions.RequestException as e:
            self.error(str(e))

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='Netcraft:takedown')]


if __name__ == '__main__':
    NetcraftReporter().run()
