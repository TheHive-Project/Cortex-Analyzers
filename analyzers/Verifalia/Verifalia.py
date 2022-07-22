#!/usr/bin/env python
import time
import requests
from cortexutils.analyzer import Analyzer


class Verifalia(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.login_key = self.get_param('config.login', None, 'Missing username for Verifalia')
        self.password_key = self.get_param('config.password', None, 'Missing password for Verifalia')

    def summary(self, raw):
        taxonomies = []
        level = 'info'
        namespace = 'Verifalia'
        predicate = ':'
        value = ''
        if "entries" in raw:
            value = "{}".format(raw["classification"])
        if value == "Risky":
            level = "suspicious"
        elif value == "Deliverable":
            level = "safe"
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)
        if self.data_type == 'mail':
            try:
                input_data = self.get_data()
                with requests.Session() as s:
                    headers = {
                        'Content-Type': 'application/json',
                    }
                    data = '{ entries: [ { inputData: \'%s\' } ] }' % input_data
                    response = s.post('https://api.verifalia.com/v2.2/email-validations', headers=headers, data=data,
                                      auth=('{}'.format(self.login_key), '{}'.format(self.password_key)))
                    id_of_case = response.json()['overview']['id']
                    time.sleep(10)
                    response_details = s.get('https://api.verifalia.com/v2.2/email-validations/{}'.format(id_of_case),
                                             auth=('{}'.format(self.login_key), '{}'.format(self.password_key)))

                if response_details.status_code == 200:
                    result = response_details.json()
                    self.report(result if len(result) > 0 else {})
                else:
                    self.error('Failed to query Verifalia details. Status_code {}'.format(
                        response_details.status_code))
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    Verifalia().run()
