#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pyeti
from cortexutils.analyzer import Analyzer


class YetiAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.url = self.getParam('config.url', None, 'Missing URL for Yeti API')

    def summary(self, raw):
        count = len(raw.get('findings', []))
        value = "\"{}\" item(s)".format(count)

        result = {
            "taxonomies": [{
                "level": "info",
                "namespace": "YETI",
                "predicate": "Search",
                "value": value
            }]
        }
        return result

    def run(self):
        api = pyeti.YetiApi("{}/api/".format(self.url))
        data = self.getData()

        try:
            result = api.observable_search(value=data)
            self.report({
                'findings': result
            })
        except:
            self.error('An issue occurred while calling Yeyi API')

if __name__ == '__main__':
    YetiAnalyzer().run()
