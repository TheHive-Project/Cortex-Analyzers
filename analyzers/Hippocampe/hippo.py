#!/usr/bin/env python
# encoding: utf-8
import sys
import os
import json
import codecs
import urllib2
from cortexutils.analyzer import Analyzer


class HippoAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.url = self.getParam('config.url', None, 'Missing URL for Hippocampe API')
        self.service = self.getParam('config.service', None, 'Service parameter is missing')

    def moreSummary(self, raw):
        data = self.getData()
        result = {}
        result[data] = 0

        if(data in raw):
            result[data] = len(raw[data])

        return result

    def scoreSummary(self, raw):
        data = self.getData()
        result = {}
        if(data in raw):
            result[data] = raw[data]["hipposcore"]

        return result

    def summary(self, raw):
        taxonomy = {"level": "safe", "namespace": "Hippocampe", "predicate": "Score", "value": 0}
        taxonomies = []
        level = "safe"
        namespace = "Hippocampe"
        predicate = "Score"
        value = "\"0 record\""


        if (self.service == 'hipposcore'):
            r = self.scoreSummary(raw).get("data", 0)
            value = r
            if r > 0:
                level = "malicious"
            taxonomies.append(taxonomy)
        elif (self.service == 'more'):
            r = self.moreSummary(raw).get("data", 0)
            value = "\"{} record(s)\"".format(r)
            if r > 0:
                level = "malicious"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):
        data = self.getData()

        value = {
            data: {
                "type": self.data_type
            }
        }
        json_data = json.dumps(value)
        post_data = json_data.encode('utf-8')
        headers = {'Content-Type': 'application/json'}

        response = {}
        try:
            request = urllib2.Request(self.url + self.service, post_data, headers)
            response = urllib2.urlopen(request)
            report = json.loads(response.read())

            self.report(report)
        except urllib2.HTTPError:
            self.error("Hippocampe: " + str(sys.exc_info()[1]))
        except urllib2.URLError:
            self.error("Hippocampe: service is not available")
        except Exception as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    HippoAnalyzer().run()
