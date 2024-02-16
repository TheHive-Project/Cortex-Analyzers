#!/usr/bin/env python3
# encoding: utf-8

import intelix
import time
from cortexutils.analyzer import Analyzer


class SophosIntelixAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.clientId = self.get_param('config.clientID', None, 'ClientId is Missing')
        self.clientSecret = self.get_param('config.clientSecret', None, 'Client Secret is Missing')
        self.polling_interval = self.get_param('config.polling_interval', 60)
        try:
            self.ic = intelix.client(self.clientId, self.clientSecret)
        except Exception as e:
            error = str(e)
            self.error('Error: {}'.format(error))

    def run(self):
        if self.service == 'get':
            if self.data_type == 'hash':
                try:
                    data = self.get_data()
                    try:
                        self.ic.file_lookup(data)
                        self.report({
                            "file_hash": data,
                            "reputation_score": self.ic.reputationScore,
                            "classification": self.ic.classification
                        })
                    except TypeError:
                        self.report({
                            "file_hash": data,
                            "reputation_score": "None",
                            "classification": "Unknown"
                        })
                except Exception as e:
                    error = str(e)
                    self.error('Error: {}'.format(error))

            elif self.data_type in ('domain', 'fqdn', 'url'):
                try:
                    data = self.get_data()
                    self.ic.url_lookup(data)
                    self.report({
                        "prod_category": self.ic.productivityCategory,
                        "sec_category": self.ic.securityCategory,
                        "risk_level": self.ic.riskLevel
                    })
                except:
                    self.error('Error running URL lookup on {}'.format(data))
            else:
                self.error('Unsupported Data Type')
        elif self.service == "submit_static":
            filepath = self.get_param('file', None, 'File is missing')
            self.ic.submit_file(filepath, "static")
            self.ic.file_report_by_jobid(self.ic.jobId, "static")

            while self.ic.report is None:
                time.sleep(self.polling_interval)
                self.ic.file_report_by_jobid(self.ic.jobId, "static")
            else:
                self.report(self.ic.report)

        elif self.service == "submit_dynamic":
            filepath = self.get_param('file', None, 'File is missing')
            self.ic.submit_file(filepath, "dynamic")
            self.ic.file_report_by_jobid(self.ic.jobId, "dynamic")

            while self.ic.report is None:
                time.sleep(self.polling_interval)
                self.ic.file_report_by_jobid(self.ic.jobId, "dynamic")
            else:
                self.report(self.ic.report)
        else:
            self.error('Invalid Service Type')

    def summary(self, raw):

        taxonomies = []
        namespace = "Intelix"

        if self.service == 'get':
            if self.data_type in ('domain', 'fqdn', 'url'):
                if self.ic.riskLevel == "UNCLASSIFIED":
                    level = "info"
                elif self.ic.riskLevel == "TRUSTED":
                    level = "safe"
                elif self.ic.riskLevel == "LOW":
                    level = "info"
                elif self.ic.riskLevel == "MEDIUM":
                    level = "suspicious"
                elif self.ic.riskLevel == "HIGH":
                    level = "malicious"
                else:
                    level = "info"

                result = {
                    "has_result": True
                }

                predicate = "RiskLevel"
                value = "{}".format(self.ic.riskLevel)

                taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
                return {"taxonomies": taxonomies}

            elif self.data_type == 'hash':
                if (self.ic.reputationScore <= 19):
                    level = "malicious"
                elif (self.ic.reputationScore > 19 and self.ic.reputationScore <= 29):
                    level = "suspicious"
                elif (self.ic.reputationScore > 29 and self.ic.reputationScore <= 69):
                    level = "suspicious"
                elif (self.ic.reputationScore > 69 and self.ic.reputationScore <= 100):
                    level = "safe"
                else:
                    level = "info"

                result = {
                    "has_result": True
                }

                predicate = "Score"
                value = "{} - {}".format(self.ic.reputationScore, self.ic.classification)

                taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
                return {"taxonomies": taxonomies}

        elif (self.service == "submit_static") or (self.service == "submit_dynamic"):

            result = {
                "has_result": True
            }

            predicate = "Score"
            value = "{}".format(self.ic.report.get("score"))

            if (self.ic.report.get("score") <= 19):
                level = "malicious"
            elif (self.ic.report.get("score") > 19 and self.ic.report.get("score") <= 29):
                level = "suspicious"
            elif (self.ic.report.get("score") > 29 and self.ic.report.get("score") <= 69):
                level = "suspicious"
            elif (self.ic.report.get("score") > 69 and self.ic.report.get("score") <= 100):
                level = "safe"
            else:
                level = "info"

            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
            return {"taxonomies": taxonomies}


if __name__ == '__main__':
    SophosIntelixAnalyzer().run()
