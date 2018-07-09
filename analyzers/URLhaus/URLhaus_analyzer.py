#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from URLhaus import URLhaus


class URLhausAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def search(self, indicator):
        """
        Searches for a website using the indicator
        :param indicator: domain, url, hash
        :type indicator: str
        :return: dict
        """
        return URLhaus(indicator).search()

    def run(self):
        targets = ["domain", "url", "hash"]
        if self.get_data() is not None and self.data_type in targets:
            self.report({
                'results': self.search(self.get_data())
            })

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "URLhaus"
        predicate = "Search"
        value = "0 result"

        results = raw["results"]
        if len(results) >= 1:
            level = "malicious"

        if len(results) <= 1:
            value = "{} result".format(len(results))
        else:
            value = "{} results".format(len(results))

        taxonomies.append(
            self.build_taxonomy(level, namespace, predicate, value)
        )

        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    URLhausAnalyzer().run()
