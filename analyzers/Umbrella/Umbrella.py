#!/usr/bin/env python3
# encoding: utf-8
import json
import requests
from cortexutils.analyzer import Analyzer

class UmbrellaAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.api_key = self.get_param('config.api_key', None, 'api_key is missing')
        self.api_secret = self.get_param('config.api_secret', None, 'api_secret is missing')
        self.organization_id = self.get_param('config.organization_id', None, 'organization_id is missing')
        self.query_limit = str(self.get_param('config.query_limit', 20))

    def umbrella_runreport(self, destination):
        base_url = "https://reports.api.umbrella.com/v1/organizations"
        url = "{}/{}/destinations/{}/activity?limit={}".format(base_url,self.organization_id,destination,self.query_limit)
        try:
            r = requests.get(url, auth=(self.api_key, self.api_secret))
            if r.status_code == 200:
                return json.loads(r.text)
            else:
                self.error('API query failed. Check parameters.')
        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        taxonomies = []

        if len(raw['requests']) > 0:
            taxonomies.append(self.build_taxonomy(
                'info',
                'Umbrella',
                'Hits',
                'True'))
        else:
            taxonomies.append(self.build_taxonomy(
                'info',
                'Umbrella',
                'Hits',
                'False'))

        return {'taxonomies': taxonomies}


    def run(self):
        if self.service == 'get':
            if self.data_type == 'domain':
                data = self.get_param('data', None, 'Data is missing')
                r = self.umbrella_runreport(data)
                self.report(r)
            else:
                self.error('Invalid data type')
        else:
            self.error('Invalid service type')

if __name__ == '__main__':
        UmbrellaAnalyzer().run()
