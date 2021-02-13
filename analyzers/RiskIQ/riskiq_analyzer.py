#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import json
import requests
import base64

class RiskIQAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'RiskIQ service is missing')
        self.api_key = self.get_param('config.key', None, 'RiskIQ API key is missing')
        self.api_secret = self.get_param('config.secret', None, 'RiskIQ API secret is missing')
        # https://api.riskiq.net/api/concepts.html
        self.basic_token = base64.b64encode((self.api_key+":"+self.api_secret).encode()).decode()
        self.URL = "https://api.riskiq.net/v0/"

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "RiskIQ"

        result = {}
        # passive dns service
        if self.service == 'passive_dns_ip':
            predicate = "PassiveDNS IP"
            if 'recordCount' in raw and raw['recordCount']:
                result['total'] = raw['recordCount']
            else:
                result['total'] = 0
            if result['total'] < 2:
                value = "{} record".format(result['total'])
            else:
                value = "{} records".format(result['total'])

            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):
        data = self.get_data()

        try:
            # passive dns service
            if self.service == 'passive_dns_ip':
                URI = 'pdns/data/ip?max=1000&ip='
                headers = {'Authorization': 'Basic ' + self.basic_token, 'Accept': 'application/json'}
                r = requests.get(self.URL+URI+data, headers=headers)
                if r.status_code==200:
                    result = json.loads(r.text)
                    self.report(result)
                elif r.status_code==204:
                    result={'Message':'No result'}
                    self.report(result)
            else:
                self.error('Unknown RiskIQ service')

        except Exception as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    RiskIQAnalyzer().run()
