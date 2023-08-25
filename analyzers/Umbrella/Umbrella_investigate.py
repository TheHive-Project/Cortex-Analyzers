#!/usr/bin/env python3
# encoding: utf-8
import json
import requests
from cortexutils.analyzer import Analyzer


class UmbrellaAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.bearer_token = self.get_param('config.bearer_token', None, 'bearer_token is missing')

    def umbrella_newly_seen(self, search, timeframe, offset):
        base_url = "https://investigate.api.umbrella.com/search/"
        url = f"{base_url}/{search}/?includecategory=false&limit=100&start={timeframe}&offset={offset}"
        print(url)
        try:
            r = requests.get(url, headers={'Authorization': f'Bearer {self.bearer_token}'})
            print(self.bearer_token)
            if r.status_code == 200:
                return json.loads(r.text)
            else:
                self.error('API query failed. Check parameters.')
        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Investigate"
        if self.service == 'newly_seen':
            value = "{}".format(raw['records']['totalResults'])
            taxonomies.append(self.build_taxonomy(level, namespace, 'nb_results', value))

        return {'taxonomies': taxonomies}

    def run(self):
        if self.service == 'newly_seen':
            data = self.get_param('data', None, 'Data is missing')
            timeframe = self.get_param('timeframe', "-1days")
            offset = self.get_param('offset', "0")
            r = self.umbrella_newly_seen(data, timeframe, offset)
            self.report(r)
        else:
            self.error('Invalid service name')


if __name__ == '__main__':
    UmbrellaAnalyzer().run()
