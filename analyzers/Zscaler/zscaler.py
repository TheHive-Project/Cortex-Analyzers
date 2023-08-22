#!/usr/bin/env python3
# encoding: utf-8

import os
import requests
import json
import time
from urllib.parse import urlparse
from cortexutils.analyzer import Analyzer


class ZscalerAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param('config.api_key', None, 'Zscaler API key is missing')
        self.base_uri = self.get_param('config.base_uri', None, 'Zscaler base URI is missing')
        self.username = self.get_param('config.username', None, 'Zscaler username is missing')
        self.password = self.get_param('config.password', None, 'Zscaler password is missing')
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Cortex-Analyzer'
        }

    def summary(self, raw):
        taxonomies = []

        if 'urlClassifications' in raw:
            url = raw.get('url')
            mal_category = self.get_param('config.malicious_categories', [])
            sus_category = self.get_param('config.suspicious_categories', [])
            url_classification = raw.get('urlClassifications', [])
            url_sec_classification = raw.get('urlClassificationsWithSecurityAlert', [])

            if url_classification:
                if set(url_classification).intersection(mal_category):
                    value = ", ".join(set(url_classification).intersection(mal_category))
                    level = "malicious"
                elif set(url_classification).intersection(sus_category):
                    value = ", ".join(set(url_classification).intersection(sus_category))
                    level = "suspicious"
                else:
                    value = ", ".join(url_classification)
                    level = "info"

            if url_sec_classification:
                if set(url_sec_classification).intersection(mal_category):
                    value = ", ".join(set(url_sec_classification).intersection(mal_category))
                    level = "malicious"
                elif set(url_sec_classification).intersection(sus_category):
                    value = ", ".join(set(url_sec_classification).intersection(mal_category))
                    level = "suspicious"
                else:
                    value = url_sec_classification
                    level = "suspicious"

        else:
            level = "info"

        taxonomies.append(self.build_taxonomy(level, "Zscaler", "Classification", value))
        result = {"taxonomies": taxonomies}

        return result


    def run(self):
        Analyzer.run(self)

        if self.data_type == 'domain' or self.data_type == 'fqdn'  or self.data_type == 'ip' or self.data_type == 'url':
            data = self.get_param('data', None, 'Data is missing')

            # Mange the schema part of URLs
            if self.data_type == 'url':
               url_data = urlparse(data)
               data = url_data.netloc + url_data.path + url_data.params + url_data.query

            # Get JSESSIONID
            now = str(int(time.time() * 1000))
            n = now[-6:]
            r = str(int(n) >> 1).zfill(6)
            obfuscated_key = ""
            for i in range(0, len(n), 1):
                obfuscated_key += self.api_key[int(n[i])]
            for j in range(0, len(r), 1):
                obfuscated_key += self.api_key[int(r[j])+2]

            payload = {
                "username": self.username,
                "password": self.password,
                "apiKey": obfuscated_key,
                "timestamp": int(now)
            }

            session = requests.Session()

            url_to_query = []
            url_to_query.append(data)
            r = session.post(self.base_uri + '/api/v1/authenticatedSession', headers=self.headers, json=payload)
            s = session.post(self.base_uri + '/api/v1/urlLookup', headers=self.headers, json=url_to_query)
            s.close()
            response = s.json()
            try:
                self.report(response[0])
            except Exception as e:
                self.error('Invalid data type')
        else:
            self.error('Invalid data type')

if __name__ == '__main__':
    ZscalerAnalyzer().run()

