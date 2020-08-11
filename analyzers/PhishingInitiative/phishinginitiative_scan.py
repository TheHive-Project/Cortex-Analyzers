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
        value = "\"Clean\""

        if raw["status"] == "phishing":
            level = "malicious"
            value = "\"{}\"".format(raw["status"])
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        data = self.get_data()

        try:
            p = PyEUPI(self.phishinginitiative_key)
            api_response = p.post_submission(url=data, comment="Submitted by Cortex")
            api_response_url = "".join(api_response["url"])

            if "Elle a été marquée comme étant du phishing" in api_response_url:
                self.report({"status":"phishing"})
            elif "Elle est en cours d'analyse" in api_response_url:
                self.report({"status":"analyzing"})
            elif "Elle n'est pas considérée comme étant du phishing" in api_response_url:
                self.report({"status":"clean"})
            else:
                self.report({"status":"report"})
        except Exception:
            self.unexpectedError("Service unavailable")

if __name__ == '__main__':
    PhishingInitiativeAnalyzer().run()
