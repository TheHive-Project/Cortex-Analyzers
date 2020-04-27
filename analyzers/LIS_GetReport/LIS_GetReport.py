#!/usr/bin/env python3
# -*- coding: utf-8 -*
from cortexutils.analyzer import Analyzer
import requests

class LIS_GetReport(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param("config.apiKey", None, "LastInfoSec API KEY is required")
        self.observable_value = self.get_param('data', None, 'Data is missing')


    def run(self):
        url = "https://api.client.lastinfosec.com/v2/lis/search_hash/{0}?key={1}".format(self.observable_value,
                                                                                         self.api_key)
        if self.data_type == 'domain':
            url = "https://api.client.lastinfosec.com/v2/lis/search_hash/{0}?key={1}".format(self.observable_value,
                                                                                             self.api_key)

        useragent = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) Gecko/20100101 Firefox/41.0'}
        response = requests.get(url, headers=useragent)
        self.report(self.check_response(response))

    def check_response(self, response):
        if response.status_code != 200:
            self.error('Bad status: {0}'.format(response.status_code))
        else:
            try:
                result = response.json()
                return result
            except Exception as ex:
                self.error("Bad Response: {0}".format(ex))
                return {}


    def summary(self, raw):
        raw = raw["message"][0]
        taxonomies = []
        level = "info"
        namespace = "LastInfoSec"
        predicate = "GetReport"
        value = 0
        data = next((ioc for ioc in raw["IOCs"]
                    if ioc["Value"] == self.observable_value), None)
        if data is not None:
            level = data["Risk"].lower()
            if level == "malicious":
                value = 86
            elif level == "high suspicious":
                value = 71
                level = "suspicious"
            else:
                value = 31

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

if __name__ == '__main__':
    LIS_GetReport().run()
