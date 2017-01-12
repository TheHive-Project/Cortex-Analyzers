#!/usr/bin/env python
# encoding: utf-8


import re
import requests
from cortexutils.analyzer import Analyzer


class URLCategoryAnalyzer(Analyzer):

    def summary(self, raw):
        return {'category': raw['category']}

    def run(self):
        Analyzer.run(self)

        if self.data_type == 'domain' or self.data_type == 'url':
            try:
                pattern = re.compile("(?:Category: )([\w\s]+)")
                baseurl = 'http://www.fortiguard.com/iprep?data='
                tailurl = '&lookup=Lookup'
                url = baseurl + self.getData() + tailurl
                req = requests.get(url)
                category_match = re.search(pattern, req.content, flags=0)
                self.report({
                    'category': category_match.group(1)
                })
            except ValueError as e:
                self.unexpectedError(e)
        else:
            self.notSupported()

if __name__ == '__main__':
    URLCategoryAnalyzer().run()
