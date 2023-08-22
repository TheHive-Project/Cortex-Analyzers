#!/usr/bin/env python3
# encoding: utf-8

import requests
from cortexutils.analyzer import Analyzer

class CyberprotectAnalyzer(Analyzer):

    URL = "https://api.threatscore.cyberprotect.cloud/api/v3/observables/search/by-value"

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')

    def summary(self, raw):
        taxonomies = []
        namespace = "Cyberprotect"
        if self.service == 'ThreatScore':
            level = 'info'
            value = 'not in database'
            if 'threatscore' in raw:
                value = 'not analyzed yet'
                if 'value' in raw['threatscore'] and 'level' in raw['threatscore']:
                    value = raw['threatscore']['value']
                    level = raw['threatscore']['level']
            taxonomies.append(self.build_taxonomy(level, namespace, self.service, value))
        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)
        if self.service == 'ThreatScore' and (self.data_type == 'domain' or self.data_type == 'hash' or self.data_type == 'ip' or self.data_type == 'url' or self.data_type == 'user-agent'):
            try:
                response = requests.post(self.URL, json = { 'data' : self.get_data() })
                result = response.json()
                self.report(result)
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()

if __name__ == '__main__':
    CyberprotectAnalyzer().run()
