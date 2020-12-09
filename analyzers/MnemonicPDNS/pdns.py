#!/usr/bin/env python3
# encoding: utf-8

import requests
from cortexutils.analyzer import Analyzer


class PDNSv3(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        self.base_url = "https://portal.mnemonic.no/web/api/pdns/v3"
        self.apikey = self.get_param("config.key", None)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')

        self.headers = {
            "User-Agent": "Cortex 2",
            "Accept": "application/json"
        }
        self.params = {
            "aggregate": "true",
            "limit": "0"
        }
        self.response = None

    def get_pdns(self, content):

        url = '{0}/{1}'.format(self.base_url, content)
        r = requests.get(url, params=self.params, headers=self.headers)

        content = r.json()

        return content

    def run(self):

        result = {}
        content = self.getData()

        if self.service == "closed":
            # Fetch InHouse PDNS data.
            self.predicate = "InHouse"
            self.level = "suspicious"
            self.params["includeAnonymous"] = "false"

            if not self.apikey:
                self.error("Missing API key")

            self.headers["Argus-API-Key"] = self.apikey

        elif self.service == "public":
            # Fetch Public PDNS data
            self.predicate = "Public"
            self.level = "info"
            self.params["includeAnonymous"] = "true"

        else:
            # Did not match any services
            self.error("Invalid service")

        response = self.get_pdns(content)
        self.response = response

        result["findings"] = response

        return self.report(result)

    def summary(self, raw_report):

        return {
            "count": self.response["count"],
            "size": self.response["size"],
            "metaData": self.response["metaData"],
            "messages": self.response["messages"],
            "responseCode": self.response["responseCode"],
            "taxonomies": [{
                "namespace": "MN_PDNS",
                "predicate": self.predicate,
                "value": self.response['count'],
                "level": self.level
            }]
        }


if __name__ == '__main__':
    PDNSv3().run()
