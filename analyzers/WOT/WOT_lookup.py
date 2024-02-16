#!/usr/bin/env python3
# encoding: utf-8
import json
import requests
import datetime
from cortexutils.analyzer import Analyzer


class WOTAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.WOT_id = self.get_param('config.user', None,
                                      'Missing WOT API user')        
        self.WOT_key = self.get_param('config.key', None,
                                      'Missing WOT API key')

    def wot_checkurl(self, data):
        url = 'http://scorecard.api.mywot.com/v3/targets?t={}'.format(data)
        headers = {
            'x-user-id': self.WOT_id,
            'x-api-key': self.WOT_key
        }
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            return r.json()[0]
        else:
            self.error("{}{}".format(r.status_code, r.text))

    def summary(self, raw):
        taxonomies = []
        value = "-"
        level = "info"

        categories = [x.get('name', None) for x in raw.get("categories", [])]
        blacklists = raw.get("blackList", [])
        min_categories = min([x.get('id', 501) for x in raw.get("categories", [])])

        if categories:
            value = "|".join(categories)         
            if min_cat > 300:
                level = "safe"
            elif min_cat > 200:
                level = "suspicious"
            else:
                level = "malicious"

        if blacklists:
            value = "|".join(blacklists)
            level = "malicious"


        taxonomies.append(self.build_taxonomy(level, "WOT", "Category", "{}".format(value)))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type in ['domain', 'fqdn']:
            data = self.get_param('data', None, 'Data is missing')
            r = self.wot_checkurl(data)
            if r:
                self.report(r)
        else:
            self.error('Invalid data type')


if __name__ == '__main__':
    WOTAnalyzer().run()
