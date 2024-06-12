#!/usr/bin/env python3
import requests
import json

from cortexutils.analyzer import Analyzer


class RobtexAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.mode = self.get_param('config.service', None, 'No service given.')

    def query_ip(self):
        """
        Queries robtex api using an ip as parameter

        :return: Dictionary containing results
        :rtype: dict
        """
        return requests.get('https://freeapi.robtex.com/ipquery/{}'.format(self.get_data())).json()

    def query_rpdns(self):
        """
        Queries robtex reverse pdns-api using an ip as parameter

        :return: Dictionary containing results
        :rtype: list
        """
        results = requests.get('https://freeapi.robtex.com/pdns/reverse/{}'.format(self.get_data())).text.split('\r\n')
        jsonresults = []
        for idx, r in enumerate(results):
            if len(r) > 0:
                jsonresults.append(json.loads(r))
        return jsonresults

    def query_fpdns(self):
        """
        Queries robtex forward pdns-api using an fqdn or domain as parameter

        :return: Dictionary containing results
        :rtype: dict
        """
        results = requests.get('https://freeapi.robtex.com/pdns/forward/{}'.format(self.get_data())).text.split('\r\n')
        jsonresults = []
        for idx, r in enumerate(results):
            if len(r) > 0:
                jsonresults.append(json.loads(r))
        return jsonresults

    def run(self):
        if self.mode == 'ipquery' and self.get_param('dataType', None) == 'ip':
            self.report({"ip": self.query_ip()})
        elif self.mode == 'rpdnsquery' and self.get_param('dataType', None) == 'ip':
            self.report({"rpdns": self.query_rpdns()})
        elif self.mode == 'fpdnsquery' and self.get_param('dataType', None) in ['fqdn', 'domain']:
            self.report({"fpdns": self.query_fpdns()})
        else:
            self.error('Service or data type not supported by this analyzer.')

    def summary(self, raw):
        taxonomies = []
        if self.mode == 'ipquery':
            if len(raw['ip']['act']) > 0:
                taxonomies.append(self.build_taxonomy(
                    'suspicious',
                    'Robtex',
                    'ActiveDNS',
                    '{} entries'.format(len(raw['ip']['act']))
                ))
            if len(raw['ip']['acth']) > 0:
                taxonomies.append(self.build_taxonomy(
                    'suspicious',
                    'Robtex',
                    'ActiveDNSHistory',
                    '{} entries'.format(len(raw['ip']['acth']))
                ))
            if len(raw['ip']['pas']) > 0:
                taxonomies.append(self.build_taxonomy(
                    'suspicious',
                    'Robtex',
                    'PassiveDNS',
                    '{} entries'.format(len(raw['ip']['pas']))
                ))
            if len(raw['ip']['pash']) > 0:
                taxonomies.append(self.build_taxonomy(
                    'suspicious',
                    'Robtex',
                    'PassiveDNSHistory',
                    '{} entries'.format(len(raw['ip']['pash']))
                ))
        elif self.mode == 'rpdnsquery':
            if len(raw['rpdns']) > 0:
                taxonomies.append(self.build_taxonomy(
                    'suspicious',
                    'Robtex',
                    'ReversePassiveDNS',
                    '{} entries'.format(len(raw['rpdns']))
                ))
        elif self.mode == 'fpdnsquery':
            if len(raw['fpdns']) > 0:
                taxonomies.append(self.build_taxonomy(
                    'suspicious',
                    'Robtex',
                    'ForwardPassiveDNS',
                    '{} entries'.format(len(raw['fpdns']))
                ))
        return {'taxonomies': taxonomies}


if __name__ == '__main__':
    RobtexAnalyzer().run()
