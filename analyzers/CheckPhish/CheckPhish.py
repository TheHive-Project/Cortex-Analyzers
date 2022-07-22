#!/usr/bin/env python
import time
import requests
from cortexutils.analyzer import Analyzer


class CheckPhish(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.test_key = self.get_param('config.key', None, 'Missing API key for CheckPhish')

    def summary(self, raw):
        taxonomies = []
        level = 'info'
        namespace = 'CheckPhish'
        predicate = ':'
        value = ''
        if "jobID" in raw:
            value = "{}".format(raw["jobID"])

        if "disposition" in raw:
            value = "{}".format(raw["disposition"])
            if value == "clean":
                level = "safe"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)
        if self.data_type == 'url':
            try:
                input_data = self.get_data()
                with requests.Session() as s:
                    headers = {
                        'Content-Type': 'application/json',
                    }
                data = '{ "apiKey": "%s", "urlInfo": { "url": "%s" } }' % (self.test_key, input_data)
                response_details = s.post('https://developers.checkphish.ai/api/neo/scan', headers=headers,
                                          data=data)
                if response_details.status_code == 200:
                    result = response_details.json()
                    self.report(result if len(result) > 0 else {})
                else:
                    self.error('Failed to query CheckPhish details. Status_code {}'.format(
                        response_details.status_code))
            except Exception as e:
                self.unexpectedError(e)

        elif self.data_type == 'string':
            try:
                input_data = self.get_data()
                headers = {
                    'Content-Type': 'application/json',
                }
                data = '{"apiKey": "%s", "jobID": "%s", "insights": true}' % (self.test_key, input_data)
                response_details = requests.post('https://developers.checkphish.ai/api/neo/scan/status',
                                                 headers=headers,
                                                 data=data)
                if response_details.status_code == 200:
                    result = response_details.json()
                    self.report(result if len(result) > 0 else {})
                else:
                    self.error('Failed to query CheckPhish details. Status_code {}'.format(
                        response_details.status_code))

            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    CheckPhish().run()
