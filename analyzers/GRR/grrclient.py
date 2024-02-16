#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
from grr_api_client import api


class GRRAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.grr_url = self.get_param('config.url', None, 'Missing GRR API endpoint')
        self.grr_user = self.get_param('config.username', None, 'Missing GRR username')
        self.grr_passwd = self.get_param('config.password', None, 'Missing GRR password')
        self.proxies = self.get_param('config.proxy', None)
        self.grrapi = api.InitHttp(api_endpoint=self.grr_url, auth=(self.grr_user, self.grr_passwd))

    def summary(self, raw):
        taxonomies = []
        level = 'info'
        namespace = 'GRR'
        predicate = 'Client id'
        
        for client_id in raw['results']:
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, client_id))

        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'ip' or self.data_type == 'fqdn':
            search_result = self.grrapi.SearchClients(self.get_data())
            result = []
            for client in search_result:
                result.append(client.client_id)
            self.report({'results': result})
        else:
            self.error('Invalid data type')

if __name__ == '__main__':
    GRRAnalyzer().run()
