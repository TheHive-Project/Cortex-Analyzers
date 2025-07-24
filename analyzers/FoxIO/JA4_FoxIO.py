#!/usr/bin/env python3
# Author: @cyber_pescadito
from cortexutils.analyzer import Analyzer
import requests
import json

class JA4_FoxIO(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.data = self.get_param('data', None, 'Data is missing')
        self.data_type = self.get_param('dataType', None, 'dataType is missing')

    def run(self):
        Analyzer.run(self)
        try:
            db = requests.get('https://ja4db.com/api/read/')
            jsoned = json.loads(db.text)

            report_content = []

            if self.data_type == 'user-agent':
                for item in jsoned:
                    user_agent_string = item.get('user_agent_string')
                    if user_agent_string and self.data == user_agent_string:
                        report_content.append(item)
            elif self.data_type == 'ja4-fingerprint':
                fingerprint_fields = [
                    "ja4_fingerprint",
                    "ja4_fingerprint_string",
                    "ja4s_fingerprint",
                    "ja4h_fingerprint",
                    "ja4x_fingerprint",
                    "ja4t_fingerprint",
                    "ja4ts_fingerprint",
                    "ja4tscan_fingerprint"
                    ]

            for item in jsoned:
                if any(self.data == item.get(field) for field in fingerprint_fields):
                    report_content.append(item)

            self.report({"report": report_content})


        except Exception as e:
            self.error(str(e))

    def summary(self, report_content):
        taxonomies = []
        level = 'info'
        namespace = "JA4"
        predicate = "Reports count"
        value = str(len(report_content['report']))

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    JA4_FoxIO().run()