#!/usr/bin/env python
import requests
from cortexutils.analyzer import Analyzer


class KasperskyTIP(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.test_key = self.get_param('config.key', None, 'Missing Kaspersky Threat Intelligence Portal API key')

    def summary(self, raw):
        taxonomies = []
        level = 'info'
        namespace = 'KTIP'
        predicate = 'Status'
        value = "None"
        if "Zone" in raw:
            value = "{}".format(raw["Zone"])
        if value == "Green":
            level = "safe"
        elif value == "Yellow":
            level = "suspicious"
        elif value == "Red":
            level = "malicious"
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)
        if self.data_type == 'ip':
            try:
                data = self.get_data()
                headers = {
                    'x-api-key': self.test_key,
                }
                params = (
                    ('request', data),
                )
                s = requests.Session()
                response_details = s.get('https://opentip.kaspersky.com/api/v1/search/ip', headers=headers,
                                         params=params)

                if response_details.status_code == 200:
                    result = response_details.json()
                    self.report(result if len(result) > 0 else {})
                else:
                    self.error('Failed to query Kaspersky Threat Intelligence Portal details. Status_code {}'.format(
                        response_details.status_code))
            except Exception as e:
                self.unexpectedError(e)

        elif self.data_type == 'domain':
            try:
                data = self.get_data()
                headers = {
                    'x-api-key': self.test_key,
                }
                params = (
                    ('request', data),
                )
                s = requests.Session()
                response_details = s.get('https://opentip.kaspersky.com/api/v1/search/domain', headers=headers,
                                         params=params)

                if response_details.status_code == 200:
                    result = response_details.json()
                    self.report(result if len(result) > 0 else {})
                else:
                    self.error('Failed to query Kaspersky Threat Intelligence Portal details. Status_code {}'.format(
                        response_details.status_code))
            except Exception as e:
                self.unexpectedError(e)

        elif self.data_type == 'hash':
            try:
                data = self.get_data()
                headers = {
                    'x-api-key': self.test_key,
                }
                params = (
                    ('request', data),
                )
                s = requests.Session()
                response_details = s.get('https://opentip.kaspersky.com/api/v1/search/hash', headers=headers,
                                         params=params)

                if response_details.status_code == 200:
                    result = response_details.json()
                    self.report(result if len(result) > 0 else {})
                else:
                    self.error('Failed to query Kaspersky Threat Intelligence Portal details. Status_code {}'.format(
                        response_details.status_code))
            except Exception as e:
                self.unexpectedError(e)

        else:
            self.notSupported()


if __name__ == '__main__':
    KasperskyTIP().run()
