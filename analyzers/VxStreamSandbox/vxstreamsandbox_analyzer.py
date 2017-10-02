#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
According to data from official site [1], VxStream Sandbox Public API allows you to analyze:

- hash
- filename
- host / ip (some problems on API side for now)
- domain / fqdn (some problems on API side for now)

[1] https://www.hybrid-analysis.com/apikeys/info
"""

import io
import hashlib
import requests
import json
import time

from requests.auth import HTTPBasicAuth
from cortexutils.analyzer import Analyzer


class VxStreamSandboxAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.basic_url = 'https://www.hybrid-analysis.com/api/'
        self.headers = {'User-Agent': 'VxStream'}

        self.secret = self.getParam('config.secret', None, 'VxStream Sandbox secret key is missing')
        self.api_key = self.getParam('config.api_key', None, 'VxStream Sandbox API key is missing')

    def summary(self, raw_report):
        taxonomies = []

        # default values
        level = "info"
        namespace = "VxStreamSB"
        predicate = "Threat level"
        value = "\"No verdict\""

        # define json keys to loop
        if (self.data_type == 'hash') or (self.data_type == 'file'):
            minireports = raw_report[u'results'][u'response']
        elif self.data_type == 'filename':
            minireports = raw_report[u'results'][u'response'][u'result']

        # get first report with not Null verdict
        for minireport in minireports:
            if minireport[u'verdict'] is not None:
                report_verdict = minireport[u'verdict']
                break

        # create shield badge for short.html
        if report_verdict == 'malicious':
            level = 'malicious'
            value = "\"Malicious\""
        elif report_verdict == 'suspicious':
            level = 'suspicious'
            value = "\"Suspicious\""
        elif report_verdict == 'whitelisted':
            level = 'safe'
            value = "\"Whitelisted\""
        elif report_verdict == 'no specific threat':
            level = 'info'
            value = "\"No Specific Threat\""

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):

        try:
            if self.data_type == 'hash':
                query_url = 'scan/'
                query_data = self.getParam('data', None, 'Hash is missing')

            elif self.data_type == 'file':
                query_url = 'scan/'
                hashes = self.getParam('attachment.hashes', None)

                if hashes is None:
                    filepath = self.getParam('file', None, 'File is missing')
                    query_data = hashlib.sha256(open(filepath, 'r').read()).hexdigest()
                else:
                    # find SHA256 hash
                    query_data = next(h for h in hashes if len(h) == 64)

            elif self.data_type == 'filename':
                query_url = 'search?query=filename:'
                query_data = self.getParam('data', None, 'Filename is missing')
            else:
                self.notSupported()

            url = str(self.basic_url) + str(query_url) + str(query_data)

            error = True
            while error:
                r = requests.get(url, headers=self.headers, auth=HTTPBasicAuth(self.api_key, self.secret))
                if r.json()[u'response'][
                    u'error'] == "Exceeded maximum API requests per minute(5). Please try again later.":
                    time.sleep(60)
                else:
                    error = False

            self.report({'results': r.json()})

        except ValueError as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    VxStreamSandboxAnalyzer().run()
