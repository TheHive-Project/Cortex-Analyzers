#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from urlscan import Urlscan, UrlscanException


class UrlscanAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def search(self, indicator, api_key, search_after=None):
        """
        Searches for a website using the indicator
        :param search_after:
        :param indicator: domain, ip, hash, url
        :type indicator: str
        :return: dict
        """
        res = Urlscan(indicator, self.api_key).search(search_after=search_after)
        return res

    def run(self):
        targets = ['ip', 'domain', 'hash', 'url','other']
        if self.data_type == 'url':
            query = '"{}"'.format(self.get_data())
        else:
            query = self.get_data()

        try:
            if self.data_type in targets:
                search_after = self.get_param('parameters.search_after', None, None)
                self.report({
                    'type': self.data_type,
                    'query': query+". Search after: "+search_after,
                        'indicator': self.search(query, search_after=search_after)
                })
        except UrlscanException as err:
            self.error(str(err))

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "urlscan.io"
        predicate = "Search"

        total = raw["indicator"]["total"]
        if total <= 1:
            level = 'suspicious' if total == 1 else 'info'
            value = total
            taxonomies.append(self.build_taxonomy(
                level, namespace, predicate, value))
        else:
            level = 'suspicious'
            value = total
            taxonomies.append(self.build_taxonomy(
                level, namespace, predicate, value))

        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    UrlscanAnalyzer().run()
