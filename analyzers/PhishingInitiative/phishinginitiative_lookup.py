#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.analyzer import Analyzer
from pyeupi import PyEUPI


class PhishingInitiativeAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.phishinginitiative_key = self.get_param('config.key', None,
                                                     'Missing PhishingInitiative API key')

    def summary(self, raw):
        taxonomies = []
        level = "safe"
        namespace = "PhishingInitiative"
        predicate = "Status"
        value = "Clean"

        if raw["tag_label"] == "phishing":
            level = "malicious"
            value = "{}".format(raw["tag_label"])
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        data = self.get_data()

        try:
            p = PyEUPI(self.phishinginitiative_key)
            api_response = p.lookup(url=data)

            if "status" in api_response and api_response["status"] != 200:
                self.error(api_response["message"])
            else:
                self.report(api_response["results"][0])
        except Exception:
            self.unexpectedError("Service unavailable")


if __name__ == '__main__':
    PhishingInitiativeAnalyzer().run()
