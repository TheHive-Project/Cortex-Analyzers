#!/usr/bin/env python3
import requests

from cortexutils.analyzer import Analyzer


class PulsediveAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.url = 'https://pulsedive.com/api/'
        self.key = self.get_param('config.key', None, 'API-Key not given.')
        self.mapping = {
            'high': 'malicious',
            'medium': 'suspicious',
            'low': 'info'
        }

    def _query(self, observable):
        request = self.url + 'info.php'
        result = requests.get(request, {
            'indicator': observable,
            'key': self.key
        }).json()

        if result.get('error', None) and result.get('error') != 'Indicator not found.':
            self.error(result.get('error'))
        return result

    def run(self):
        self.report(self._query(self.get_data()))

    def summary(self, raw):
        taxonomies = []
        for threat in raw.get('threats', []):
            taxonomies.append(self.build_taxonomy(
                'malicious' if threat.get('risk', '') == 'high' else 'suspicious',
                'Pulsedive',
                'Threat',
                threat.get('name')
            ))

        if raw.get('risk', None):
            taxonomies.append(self.build_taxonomy(
                self.mapping[raw['risk']],
                'Pulsedive',
                'Risk',
                raw['risk']
            ))

        return {'taxonomies': taxonomies}


if __name__ == '__main__':
    PulsediveAnalyzer().run()
