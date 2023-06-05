#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import requests


class AxurAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param(
            'config.api_key', None, 'Missing API key'
        )

    def run(self):
        if self.data_type not in ['domain', 'fqdn', 'ip', 'url', 'hash']:
            self.error('Wrong data type')

        url = f'https://api.axur.com/gateway/1.0/ioc/{self.data_type}/{self.get_data()}'

        try:
            self.report(requests.get(url, headers={'api_key': self.api_key}).json())
        except Exception as e:
            self.error(e)

    def summary(self, raw):
        value = raw.get('Score', 0)
        level = ['safe', 'suspicious', 'malicious'][value]
        return {'taxonomies': [self.build_taxonomy(level, 'Axur', 'Score', value)]}


if __name__ == '__main__':
    AxurAnalyzer().run()
