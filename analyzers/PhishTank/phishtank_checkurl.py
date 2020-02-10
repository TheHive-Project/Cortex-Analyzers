#!/usr/bin/env python3
# encoding: utf-8
import json
import requests
from cortexutils.analyzer import Analyzer


class PhishtankAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.phishtank_key = self.get_param('config.key', None,
                                            'Missing PhishTank API key')

    def phishtank_checkurl(self, data):
        url = 'https://checkurl.phishtank.com/checkurl/'
        postdata = {'url': data, 'format': 'json', 'app_key': self.phishtank_key}
        r = requests.post(url, data=postdata)
        return json.loads(r.content)

    def summary(self, raw):
        taxonomies = []
        level = "info"

        if 'in_database' in raw and raw['in_database'] is True:
            value = "{}".format(raw['in_database'])
            if raw.get('verified') and raw.get('valid'):
                level = "malicious"
            elif raw.get('verified') and raw.get('valid') is False:
                level = "safe"
            else:
                level = "suspicious"
        else:
            value = "False"

        taxonomies.append(self.build_taxonomy(level, "PhishTank", "In_Database", value))

        result = {"taxonomies": taxonomies}
        return result

    def run(self):
        if self.data_type == 'url':
            data = self.get_param('data', None, 'Data is missing')
            r = self.phishtank_checkurl(data)
            if "success" in r['meta']['status']:
                if r['results']['in_database']:
                    if "verified" in r['results']:
                        self.report({
                            'in_database': r['results']['in_database'],
                            'phish_detail_page': r['results']['phish_detail_page'],
                            'verified': r['results']['verified'],
                            'verified_at': r['results']['verified_at'],
                            'valid': r['results']['valid']
                        })
                    else:
                        self.report({
                            'in_database': r['results']['in_database'],
                            'phish_detail_page': r['results']['phish_detail_page']
                        })
                else:
                    self.report({
                        'in_database': 'False'
                    })
            else:
                self.report({
                    'errortext': r['errortext']
                })
        else:
            self.error('Invalid data type')


if __name__ == '__main__':
    PhishtankAnalyzer().run()
