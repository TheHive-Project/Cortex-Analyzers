#!/usr/bin/env python3
# encoding: utf-8
import time
import requests
import ast

from cortexutils.analyzer import Analyzer


class HIBPQueryAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.api_url = self.get_param('config.url', None, 'Missing API URL')
        self.unverified = self.get_param('config.unverified', None, 'Missing Unverified option')
        self.truncate = self.get_param('config.truncate', None, 'Missing Truncate option')
        self.api_key = self.get_param('config.api_key', None, 'Missing Api Key')
        self.retries = self.get_param('config.retries', 5, 'Missing Retries option')

    @staticmethod
    def cleanup(return_data):

        response = dict()
        matches = []

        for entry in return_data:
            x = ast.literal_eval(str(entry))
            matches.append(x)

        response['CompromisedAccounts'] = matches

        return response

    def hibp_query(self, data):
        results = dict()

        try:

            hibpurl = '{}{}?includeUnverified={}&truncateResponse={}'.format(
                self.api_url, data, self.unverified, self.truncate
            )

            headers = {
                'User-Agent': 'HIBP-Cortex-Analyzer',
                'hibp-api-key': self.api_key
            }

            _query = requests.get(hibpurl, headers=headers)
            if _query.status_code == 200:
                if _query.text == "[]":
                    return dict()
                else:
                    return self.cleanup(_query.json())
            elif _query.status_code == 404:
                return dict()
            elif _query.status_code == 429:
                retry_after = _query.headers.get('retry-after')

                # if header retry-after is missing
                if retry_after is None:
                    retry_after = 0

                self.retries = self.retries - 1
                if self.retries < 0:
                    self.error('API Access error: %s' % _query.text)

                # recursive call after waiting
                time.sleep(retry_after)
                return self.hibp_query(data)
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

        breach_count = len(raw)

        if breach_count == 0:
            level = "safe"
            value = "False"
        elif breach_count > 0:
            level = "malicious"
            value = "True"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        # Add taxonomy for breach counts
        if len(raw) > 0:
            accounts = raw.get('CompromisedAccounts', [])

            verified = len([a for a in accounts if a.get('IsVerified', None) == True])
            if verified > 0:
                taxonomies.append(self.build_taxonomy('info', 'HIBP', 'Verified', verified))

            unverified = len([a for a in accounts if a.get('IsVerified', None) == False])
            if unverified > 0:
                taxonomies.append(self.build_taxonomy('info', 'HIBP', 'Unverified',unverified))

        return {"taxonomies": taxonomies}

    def run(self):

        if self.service == 'query':
            if self.data_type == 'mail':
                data = self.get_param('data', None, 'Data is missing')
                self.report(self.hibp_query(data))
            else:
                self.error('Invalid data type')
        else:
            self.error('Invalid service')


if __name__ == '__main__':
    HIBPQueryAnalyzer().run()
