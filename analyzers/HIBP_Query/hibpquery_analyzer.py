#!/usr/bin/env python
# encoding: utf-8
import json
import requests
import ast

from cortexutils.analyzer import Analyzer


class HIBPQueryAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam(
            'config.service', None, 'Service parameter is missing')
        self.api_url = self.getParam('config.url', None, 'Missing API URL')
        self.unverified = self.getParam('config.unverified', None, 'Missing Unverified option')

    @staticmethod
    def cleanup(return_data):

        response = dict()
        matches = []
        found = False
        count = 0

        for entry in return_data:
            found = True
            x = ast.literal_eval(str(entry))
	    matches.append(x)
        response['CompromisedAccounts'] = matches

        return response

    def hibp_query(self, data):
        results = dict()

        try:
	    if self.unverified == True:
                unverified = '?includeUnverified=true'
            else:
                unverified = ''
	    hibpurl = self.api_url + data + unverified
	    headers = {
                'User-Agent': 'HIBP-Cortex-Analyzer'
	    }

            _query = requests.get(hibpurl, headers=headers)
            if _query.status_code == 200:
                if _query.text == "[]":
                    return dict()
                else:
                    return self.cleanup(_query.json())
            elif _query.status_code == 404:
                return dict()
            else:
                self.error('API Access error: %s' % _query.text)

        except Exception as e:
            self.error('API Request error: %s' % str(e))

        return results

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "HIBP"
        predicate = "Compromised"
        if len(raw) == 0:
            level = "safe"
            namespace = "HIBP"
            predicate = "Compromised"
            value = "False"
        elif len(raw) > 0:
            level = "malicious"
            namespace = "HIBP"
            predicate = "Compromised"
            value = "True"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):

        if self.service == 'query':
            if self.data_type == 'mail':
                data = self.getParam('data', None, 'Data is missing')

                rep = self.hibp_query(data)
                self.report(rep)

            else:
                self.error('Invalid data type')
        else:
            self.error('Invalid service')


if __name__ == '__main__':
    HIBPQueryAnalyzer().run()
