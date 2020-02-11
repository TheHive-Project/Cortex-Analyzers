#!/usr/bin/env python3
# encoding: utf-8
import sys
import json
import requests
from cortexutils.analyzer import Analyzer


class HippoAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.url = self.get_param('config.url', None, 'Missing URL for Hippocampe API')
        self.service = self.get_param('config.service', None, 'Service parameter is missing')

    def more_summary(self, raw):
        data = self.get_data()
        result = {
            data: 0
        }

        if data in raw:
            result[data] = len(raw.get(data))

        return result

    def score_summary(self, raw):
        data = self.get_data()
        result = {}
        if data in raw:
            result[data] = raw.get(data).get("hipposcore")
        return result

    def summary(self, raw):
        taxonomies = []
        level = "safe"
        namespace = "Hippocampe"
        predicate = "Score"

        if self.service == 'hipposcore':
            value = self.score_summary(raw)[self.get_data()]
            if value > 0:
                level = "malicious"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        elif self.service == 'more':
            value = self.more_summary(raw)[self.get_data()]
            if value > 0:
                level = "malicious"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, "{} record(s)".format(value)))

        return {"taxonomies": taxonomies}

    def run(self):
        data = self.get_data()

        value = {
            data: {
                "type": self.data_type
            }
        }
        json_data = json.dumps(value)
        post_data = json_data.encode('utf-8')
        headers = {'Content-Type': 'application/json'}
        url = '{}/hippocampe/api/v1.0/{}'.format(self.url, self.service),

        try:
            r = requests.post(url, data=post_data, headers=headers)
            report = r.json()

            self.report(report)

        except ValueError as e:
            self.unexpectedError('Unable to decode to JSON: {}'.format(e))
        except Exception as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    HippoAnalyzer().run()
