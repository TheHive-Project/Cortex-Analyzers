#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
According to data from official site [1], VxStream Sandbox Public API allows you to analyze:

- hash
- filename
- host / ip (some problems on API side for now)
- domain / fqdn (some problems on API side for now)

[1] https://www.hybrid-analysis.com/apikeys/info
"""

import hashlib
import requests
import time

from requests.auth import HTTPBasicAuth
from cortexutils.analyzer import Analyzer


class VxStreamSandboxAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.basic_url = 'https://www.hybrid-analysis.com/api/'
        self.headers = {'User-Agent': 'VxStream'}

        self.secret = self.get_param('config.secret', None, 'VxStream Sandbox secret key is missing')
        self.api_key = self.get_param('config.key', None, 'VxStream Sandbox API key is missing')

    def summary(self, raw_report):
        taxonomies = []

        # default values
        level = "info"
        namespace = "HybridAnalysis"
        predicate = "Threat level"
        value = "No verdict"

        # define json keys to loop
        if self.data_type in ['hash', 'file']:
            minireports = raw_report.get('results').get('response')
        elif self.data_type in ['filename']:
            minireports = raw_report.get('results').get('response').get('result')

        if len(minireports) != 0:
            # get first report with not Null verdict
            for minireport in minireports:
                if minireport.get('verdict') is not None:
                    report_verdict = minireport.get('verdict')
                    break

            # create shield badge for short.html
            if report_verdict == 'malicious':
                level = 'malicious'
                value = "Malicious"
            elif report_verdict == 'suspicious':
                level = 'suspicious'
                value = "Suspicious"
            elif report_verdict == 'whitelisted':
                level = 'safe'
                value = "Whitelisted"
            elif report_verdict == 'no specific threat':
                level = 'info'
                value = "No Specific Threat"
        else:
            level = 'info'
            value = "Unknown"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):

        try:
            if self.data_type == 'hash':
                query_url = 'scan/'
                query_data = self.get_param('data', None, 'Hash is missing')

            elif self.data_type == 'file':
                query_url = 'scan/'
                hashes = self.get_param('attachment.hashes', None)

                if hashes is None:
                    filepath = self.get_param('file', None, 'File is missing')
                    query_data = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
                else:
                    # find SHA256 hash
                    query_data = next(h for h in hashes if len(h) == 64)

            elif self.data_type == 'filename':
                query_url = 'search?query=filename:'
                query_data = '"{}"'.format(self.get_param('data', None, 'Filename is missing'))
            else:
                self.notSupported()

            url = str(self.basic_url) + str(query_url) + str(query_data)

            error = True
            while error:
                r = requests.get(url, headers=self.headers, auth=HTTPBasicAuth(self.api_key, self.secret), verify=True)
                if "error" in r.json().get('response'):
                    if "Exceeded maximum API requests per minute(5)" in r.json().get('response').get('error'):
                        time.sleep(60)
                    else:
                        self.error(r.json().get('response').get('error'))
                else:
                    error = False

            self.report({'results': r.json()})

        except ValueError as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    VxStreamSandboxAnalyzer().run()
