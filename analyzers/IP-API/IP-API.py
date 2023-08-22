#!/usr/bin/env python
import requests
from cortexutils.analyzer import Analyzer


class IPAPI(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

    def summary(self, raw):
        taxonomies = []
        level = 'info'
        namespace = 'IP-API'
        predicate = 'Country'
        value = "None"
        if "country" in raw:
            value = "{}".format(raw["country"])
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)
        if self.data_type == 'ip' or self.data_type == 'domain':
            try:
                data = self.get_data()
                s = requests.Session()
                response_details = s.get('http://ip-api.com/json/{}'
                                         .format(data))
                if response_details.status_code == 200:
                    result = response_details.json()
                    self.report(result if len(result) > 0 else {})
                else:
                    self.error('Failed to query IP-API details. Status_code {}'.format(response_details.status_code))
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    IPAPI().run()
