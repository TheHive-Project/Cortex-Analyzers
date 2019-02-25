#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from URLhaus_client import URLhausClient


class URLhausAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def run(self):
        data = self.get_data()
        if not data:
            self.error('No observable or file given.')

        results = {}
        if self.data_type == 'url':
            results = URLhausClient.search_url(data)
        elif self.data_type in ['domain', 'ip']:
            results = URLhausClient.search_host(data)
        elif self.data_type == 'hash':
            if len(data) in [32, 64]:
                results = URLhausClient.search_payload(data)
            else:
                self.error('Only sha256 and md5 supported by URLhaus.')
        else:
            self.error('Datatype not supported.')

        results.update({
            'data_type': self.data_type
        })
        self.report(results)

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
