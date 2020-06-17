#!/usr/bin/env python3
# encoding: utf-8

import requests
from cortexutils.analyzer import Analyzer


class Hunterio(Analyzer):
    URI = "https://api.hunter.io/v2/"


    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.key = self.get_param('config.key', None, 'Missing hunter.io API key')

    def summary(self, raw):

        taxonomies = []
        namespace = "Hunter.io"
        if self.service == 'domainsearch':
            found = 0
            if(raw.get('meta') and raw['meta'].get('results')):
                found = raw['meta'].get('results')
            taxonomies.append(self.build_taxonomy('info', namespace, "Emails found", str(found)))

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        if(raw.get('meta') and raw['meta'].get('results') > 0 ):
            for email in raw.get('data').get('emails'):
                artifacts.append({'type':'email', 'value':email.get('value')})
        return artifacts


    def run(self):
        Analyzer.run(self)

        if self.service == 'domainsearch' and (self.data_type == 'domain' or self.data_type == 'fqdn'):
            try:
                offset = 0
                firstResponse = requests.get("{}domain-search?domain={}&api_key={}&limit=100&offset={}".format(self.URI, self.get_data(), self.key, offset))
                firstResponse = firstResponse.json()

                if firstResponse.get('meta'):
                    meta = firstResponse.get('meta')

                    while meta.get('results') > offset:
                        offset = meta.get('limit') + meta.get('offset')
                        additionalResponse = requests.get("{}domain-search?domain={}&api_key={}&limit=100&offset={}".format(
                            self.URI, self.get_data(), self.key, offset))
                        additionalResponse = additionalResponse.json()
                        meta = additionalResponse.get('meta')
                        firstResponse['data']['emails'] += additionalResponse['data']['emails']

                self.report(firstResponse)
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    Hunterio().run()
