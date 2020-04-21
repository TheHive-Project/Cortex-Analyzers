#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
from emailrep import EmailRep


class EmailRepAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.key = self.get_param('config.key', None)


    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "EmailRep"

        suspicious = raw.get("suspicious", False)
        if suspicious:
            level = "suspicious"
        else:
            level = "safe"

        references = raw.get("references", 0)

        taxonomies.append(
            self.build_taxonomy(level, namespace, "References", references)
        )

        return {"taxonomies": taxonomies}

    def run(self):
        data = self.get_data()

        try:
            emailRep = EmailRep(self.key)
            result = emailRep.query(data)
            self.report(result)
        except Exception as e:
            self.error(str(e))


if __name__ == "__main__":
    EmailRepAnalyzer().run()
