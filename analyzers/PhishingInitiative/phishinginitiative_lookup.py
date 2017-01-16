#!/usr/bin/env python
# encoding: utf-8
import json
from cortexutils.analyzer import Analyzer
from pyeupi import PyEUPI

class phishinginitiativeAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.phishinginitiative_key = self.getParam('config.key', None,
                                    'Missing PhishingInitiative API key')

    def summary(self,raw):
        return {
            "status": raw["tag_label"]
        }

    def run(self):
        Analyzer.run(self)

        data = self.getData()

        try:
            p = PyEUPI(self.phishinginitiative_key)
            apiResponse = p.lookup(url=data)

            if "status" in apiResponse and apiResponse["status"] != 200:
                self.error(apiResponse["message"])
            else:
                self.report(apiResponse["results"][0])
        except:
            self.unexpectedError("Service unavailable")


if __name__ == '__main__':
    phishinginitiativeAnalyzer().run()
