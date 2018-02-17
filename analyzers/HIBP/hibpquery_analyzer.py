#!/usr/bin/env python
# encoding: utf-8
import json
import requests

from cortexutils.analyzer import Analyzer


class HIBPQueryAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam(
            'config.service', None, 'Service parameter is missing')
        self.api_url = self.getParam('config.url', None, 'Missing API URL')

    @staticmethod
    def cleanup(return_data):

        # TODO: Make this better (return the long URL for reports)
        response = dict()
        long_urls = []

        found = False

        response = return_data['artifacts']

        return response

    def hibp_query(self, data):
        results = dict()

        try:
            hibpurl = self.api_url + data
            _query = requests.get(hibpurl)
            if _query.status_code == 200:
                if _query.text == "[]":
                    return dict()
                else:
                    return self.cleanup(_query.json())
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
        value = "\"Yup\""
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):

        if self.service == 'query':
            if self.data_type == 'url':
                data = self.getParam('data', None, 'Data is missing')

                rep = self.hibp_query(data)
                self.report(rep)

            else:
                self.error('Invalid data type')
        else:
            self.error('Invalid service')


if __name__ == '__main__':
    HIBPQueryAnalyzer().run()
