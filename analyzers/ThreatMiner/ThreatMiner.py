#!/usr/bin/env python
import requests
from cortexutils.analyzer import Analyzer


class ThreatMiner(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

    def summary(self, raw):
        taxonomies = []
        level = 'suspicious'
        namespace = 'ThreatMiner'
        predicate = ':'
        value = "Not found."
        if len(raw["results"]) != 0:
            value = "Success"
            level = "safe"
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)
        if self.data_type == 'domain':
            try:
                data = self.get_data()
                s = requests.Session()
                response_details = s.get("https://api.threatminer.org/v2/domain.php?q={}&rt=1".format(data))
                if response_details.status_code == 200:
                    result = response_details.json()
                    self.report(result if len(result) > 0 else {})
                else:
                    self.error(
                        'Failed to query ThreatMiner details. Status_code {}'.format(response_details.status_code))
            except Exception as e:
                self.unexpectedError(e)
        elif self.data_type == 'ip':
            try:
                data = self.get_data()
                s = requests.Session()
                response_details = s.get("https://api.threatminer.org/v2/host.php?q={}&rt=1".format(data))
                if response_details.status_code == 200:
                    result = response_details.json()
                    self.report(result if len(result) > 0 else {})
                else:
                    self.error(
                        'Failed to query ThreatMiner details. Status_code {}'.format(response_details.status_code))
            except Exception as e:
                self.unexpectedError(e)

        else:
            self.notSupported()


if __name__ == '__main__':
    ThreatMiner().run()
