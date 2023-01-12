#!/usr/bin/env python3
import urllib
from cortexutils.analyzer import Analyzer
import requests


class publicwwwwAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param("config.api_key", None, 'Missing PublicWWW API key')

    def search(self, search_term, api_key):
        """
        Searches for a website using the indicator
        :param api_key:
        :param search_term: other
        :type search_term: str
        :return: dict
        """
        url = f"https://publicwww.com/websites/{search_term}/"
        querystring = {"export": "urls", "key": api_key}
        res = requests.request("GET", url, params=querystring)
        return res.content.decode().split('\n')[:-1]

    def run(self):
        targets = ['other']
        query = urllib.parse.quote_plus(self.get_data())
        try:
            if self.data_type in targets:
                self.report({
                    'type': self.data_type,
                    'query': query,
                    'matches': self.search(query, self.api_key)
                })
        except Exception as err:
            self.error(str(err))

    def summary(self, raw):
        taxonomies = []
        namespace = "PublicWWW"
        predicate = "search"
        total = len(raw["matches"])
        level = 'suspicious'
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, total))

        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    publicwwwwAnalyzer().run()
