#!/usr/bin/env python3
# encoding: utf-8

import requests
import re
from cortexutils.analyzer import Analyzer


class UnshortenlinkAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.url = self.get_param('url', None)
        self.proxies = self.get_param('config.proxy', None)

    def artifacts(self, raw):
        if raw['found']:
            return [{'type': 'url', 'value': raw['url']}]
        else:
            return []

    def summary(self, raw):
        taxonomies = []
        level = 'info'
        namespace = 'UnshortenLink'
        predicate = 'Result'
        value = ''

        if raw['found'] == True:
            value = 'success'
        else:
            value = 'failure'
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)

        url = self.get_data()
        if len(re.findall(
                r"^(http:\/\/)?(https:\/\/)?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]{1,5})?(\/)?$",
                url)) > 0 \
                or len(re.findall(r"^(http:\/\/)?(https:\/\/)?.+:[0-9]{1,5}$", url)) \
                or len(re.findall(r'^(http:\/\/\[)?(https:\/\/\[)('
                                  '([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'
                                  '([0-9a-fA-F]{1,4}:){1,7}:|'
                                  '([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
                                  '([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
                                  '([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
                                  '([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
                                  '([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
                                  '[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
                                  ':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
                                  'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
                                  '::(ffff(:0{1,4}){0,1}:){0,1}' + \
                                  '((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
                                  '(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'
                                  '([0-9a-fA-F]{1,4}:){1,4}:'
                                  '((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
                                  '(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
                                  ')(\])?(:[0-9]{1,5})?$', url)):
            self.error("Searching for Ports and IPs not allowed.")

        if self.proxies:
            proxies = self.proxies
        else:
            proxies = {}

        result = {'found': False, 'url': None}
        try:
            response = requests.head(url, proxies=proxies,
                                    allow_redirects=False)

            if (response.status_code == 301) or (response.status_code == 302):
                result['url'] = response.headers['Location']
                result['found'] = True
        except Exception as e:
            self.unexpectedError("Service unavailable: %s" % e)

        self.report(result)


if __name__ == '__main__':
    UnshortenlinkAnalyzer().run()
