#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.analyzer import Analyzer
from pyeupi import PyEUPI


class PhishingInitiativeAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.phishinginitiative_key = self.get_param(
            "config.key", None, "Missing PhishingInitiative API key"
        )
        self.service = self.get_param("config.service", None)

    def summary(self, raw):
        taxonomies = []
        level = "safe"
        namespace = "PhishingInitiative"
        predicate = "Status"
        value = "Clean"

        if self.service == "lookup" and raw["tag_label"] == "phishing":
            level = "malicious"
            value = "{}".format(raw["tag_label"])
        elif self.service == "scan" and raw["status"] == "phishing":
            level = "malicious"
            value = '"{}"'.format(raw["status"])
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        data = self.get_data()

        try:
            p = PyEUPI(self.phishinginitiative_key)
            if self.service == "lookup":
                api_response = p.lookup(url=data)
                if "status" in api_response and api_response["status"] != 200:
                    self.error(api_response["message"])
                else:
                    self.report(api_response["results"][0])
            elif self.service == "scan":
                api_response = p.post_submission(
                    url=data, comment="Submitted by Cortex"
                )
                if api_response["status"] == 201:
                    api_response_url = "".join(api_response["url"])

                    if "Elle a été marquée comme étant du phishing" in api_response_url:
                        self.report({"status": "phishing"})
                    elif "Elle est en cours d'analyse" in api_response_url:
                        self.report({"status": "analyzing"})
                    elif (
                        "Elle n'est pas considérée comme étant du phishing"
                        in api_response_url
                    ):
                        self.report({"status": "clean"})
                    else:
                        self.report({"status": "report"})
                else:
                    self.error("Error: {}".format(api_response["message"]))
        except Exception as e:
            self.unexpectedError("Service unavailable: {}".format(e))


if __name__ == "__main__":
    PhishingInitiativeAnalyzer().run()
