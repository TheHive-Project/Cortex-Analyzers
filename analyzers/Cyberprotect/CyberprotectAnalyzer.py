#!/usr/bin/env python3
# encoding: utf-8

import requests
from cortexutils.analyzer import Analyzer

class CyberprotectAnalyzer(Analyzer):

    URI = "https://threatscore.cyberprotect.fr/api/score/"

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')

    def summary(self, raw):
        taxonomies = []
        namespace = "Cyberprotect"
        if self.service == 'ThreatScore':
            level = 'info'
            value = 'not in database'
            if raw.get('data') and raw.get('scores') and len(raw.get('scores')) > 0:
                value = 'not analyzed yet'
                if raw['scores'][0].get('score'):
                    level = 'safe'
                    value = raw['scores'][0]['score']
                    if value >= 0.5:
                        level = 'malicious'
                    elif value >= 0.25 and value < 0.5:
                        level = 'suspicious'
            taxonomies.append(self.build_taxonomy(level, namespace, self.service, value))
        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)
        if self.service == 'ThreatScore' and (self.data_type == 'domain' or self.data_type == 'ip'):
            try:
                response = requests.get("{}{}".format(self.URI, self.get_data()))
                result = response.json()
                self.report(result if len(result) > 0 else {})
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()

if __name__ == '__main__':
    CyberprotectAnalyzer().run()
