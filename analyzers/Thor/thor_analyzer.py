#!/usr/bin/env python
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import json
import re
import requests
import time

class ThorAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.cortexURL = self.getParam('config.cortexURL', None, 'Cortex URL is missing')
        self.MISPSearch = self.getParam('config.MISPSearch', None, 'MISP Analyzer is missing')
        self.filename = self.getParam('attachment.name', 'noname.ext')
        self.filepath = self.getParam('file', None, 'File is missing')

    def runAnalyzer(self, analyzer, data, typ):
        try:
            r = requests.post(self.cortexURL+'/api/analyzer/'+analyzer+'/run', data='{"data": "'+data+'", "attributes": {"dataType": "'+typ+'", "tlp": 0}}', headers={'Content-type': 'application/json'})
            jobId = r.json()["id"]
            while True:
                res = requests.get(self.cortexURL+'/api/job/'+jobId).json()
                if res["status"] != "InProgress":
                    return res["report"]["full"]
                time.sleep(0.5)
        except Exception:
            return []

    def doMISPLookup(self, value, typ):
        result = {"value": value, "events": [], "status": None, "type": typ}
        try:
            ret = self.runAnalyzer(self.MISPSearch, value, typ)
            try:
                for mispInstance in ret["results"]:
                    for event in mispInstance["result"]:
                        # get url of event
                        event["url"] = mispInstance["url"]+"/events/view/"+event["id"]
                        result["events"].append(event)
                if len(result["events"]) > 0:
                    result["status"] = True
                else:
                    result["status"] = False
            except Exception:
                pass
        except Exception as e:
            pass
        return result
    
    def summary(self, raw):
        taxonomies = []
        
        alertsCount = len(raw.get("alerts"))
        warningsCount = len(raw.get("warnings"))

        if alertsCount > 0:
            taxonomies.append(self.build_taxonomy("malicious", "Thor", "Alerts", alertsCount))
        if warningsCount > 0:
            taxonomies.append(self.build_taxonomy("suspicious", "Thor", "Warnings", warningsCount))

        return {"taxonomies": taxonomies}

    def run(self):
        # get input data
        Analyzer.run(self)
        try:
            f = open(self.filepath, 'r')
            data = f.read()

            FIELDS = ["FILE", "SCORE", "MD5", "SHA1", "SHA256"]
            result = {}

            startupMessages = {}
            scanRegex = re.findall("Startup MESSAGE: (.*)", data)
            for scanInfo in scanRegex:
                try:
                    tmp = re.findall("([^:]+): (\S*)", scanInfo)[0]
                    startupMessages[tmp[0]] = tmp[1]
                except Exception:
                    pass

            result["startupMessages"] = startupMessages

            # get alerts
            alerts = []
            alertsRegex = re.findall("Alert:(.*)", data)
            for alert in alertsRegex:
                alertRegex = re.findall("([\w]+[_]?[0-9]?): (.*?)(?=[ ][\w]+[_]?[0-9]?: |\r)", alert)
                tmp = {}
                for t in alertRegex:
                    if (t[1] != "N/A") and (t[1] != "-"):
                        if (t[0] == "MD5") or (t[0] == "SHA1") or (t[0] == "SHA256"):
                            tmp[t[0]] = self.doMISPLookup(t[1], t[0])
                        else:
                            tmp[t[0]] = t[1]
                alerts.append(tmp)

            result["alerts"] = alerts

            # get warnings
            warnings = []
            warningsRegex = re.findall("Warning:(.*)", data)
            for warning in warningsRegex:
                warningRegex = re.findall("([\w]+[_]?[0-9]?): (.*?)(?=[ ][\w]+[_]?[0-9]?: |\r)", warning)
                tmp = {}
                for t in warningRegex:
                    if (t[1] != "N/A") and (t[1] != "-"):
                        if (t[0] == "MD5") or (t[0] == "SHA1") or (t[0] == "SHA256"):
                            tmp[t[0]] = self.doMISPLookup(t[1], t[0])
                        else:
                            tmp[t[0]] = t[1]
                warnings.append(tmp)

            result["warnings"] = warnings


            # send result
            self.report(result)

        except Exception as e:
            self.unexpectedError(e)

if __name__ == '__main__':
    ThorAnalyzer().run()