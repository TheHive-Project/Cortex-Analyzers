#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
from urllib.parse import quote_plus
import requests


class AxurAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param(
            'config.api_key', None, 'Missing Axur API key'
        )

    def run(self):
        if self.data_type not in ['domain', 'fqdn', 'ip', 'url', 'hash']:
            self.error('Wrong data type')

        encoded_data = quote_plus(self.get_data())
        url = f'https://api.axur.com/gateway/1.0/api/ioc-search/search/{self.data_type}/{encoded_data}'

        try:
            response = requests.get(url, headers={'Authorization': f'Bearer {self.api_key}'})
            response.raise_for_status()
            self.report(response.json())
        except requests.HTTPError as http_err:
            self.error('HTTP error occurred: {}'.format(http_err))
        except Exception as err:
            self.error('Error occurred: {}'.format(err))

    def summary(self, raw):
        taxonomies = []
        levels = ['info', 'safe', 'suspicious', 'malicious']

        for data in raw['results']:
            level = levels[data.get('score', 0)]
            taxonomies.append(
                self.build_taxonomy(level, 'Axur', data['source'], data.get('hits', 0))
            )

        return {'taxonomies': taxonomies}


if __name__ == '__main__':
    AxurAnalyzer().run()
