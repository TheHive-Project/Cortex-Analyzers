#!/usr/bin/env python3
# -*- coding: utf-8 -*

import requests
from cortexutils.analyzer import Analyzer
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class StaxxAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.auth_url = self.get_param('config.auth_url', None, 'Missing URL for Staxx API auth')
        self.query_url = self.get_param('config.query_url', None, 'Missing URL for Staxx API query')
        self.username = self.get_param('config.username', None, 'Missing username for Staxx API')
        self.password = self.get_param('config.password', None, 'Missing password for Staxx API')
        if self.get_param('config.cert_check', True):
            self.ssl = self.get_param('config.cert_path', True)
        else:
            self.ssl = False

    def _get_headers(self):
        return {
            'Content-Type': 'application/json'
        }

    def _get_auth_data(self):
        return {
            'username': self.username,
            'password': self.password
        }

    def staxx_query(self, data):
        headers = self._get_headers()
        auth_data = self._get_auth_data()
        r = requests.post(self.auth_url, json=auth_data, headers=headers, verify=self.ssl)
        r.raise_for_status()  # Raise exception on HTTP errors
        token_id = r.json()['token_id']
        pull_data = {'token': token_id, 'query': data, 'type': 'json'}
        p = requests.post(self.query_url, json=pull_data, headers=headers, verify=self.ssl)
        p.raise_for_status()  # Raise exception on HTTP errors
        return p.json()

    def summary(self, raw):
        taxonomies = []
        namespace = "Staxx"
        predicate = " Hits"
        value = "\0"

        if 'count' in raw:
            r = raw.get('count', 0)

            value = "{}".format(r)

            if r > 0:
                level = "suspicious"
            else:
                level = "safe"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)
        data = self.get_param('data', None, 'Data is missing')
        hits = self.staxx_query(data)
        self.report({'hits': hits, 'count': len(hits)})


if __name__ == '__main__':
    StaxxAnalyzer().run()
