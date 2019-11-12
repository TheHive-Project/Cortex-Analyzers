#!/usr/bin/env python3
# encoding: utf-8

import intelix
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
                    self.ic.file_lookup(data)
                    self.report({"classification": self.ic.classification})
                except Exception as e:
                    error = str(e)
                    self.error('Error: {}'.format(error))
            elif self.data_type == 'domain':
                try:
                    data = self.get_data()
                    self.ic.url_lookup(data)
                except:
                    self.error('Error running URL lookup on {}'.format(data))
            else:
                self.error('Unsupported Data Type')
        else:
            self.error('Invalid Service Type')

    def summary(self, raw):

        taxonomies = []
        namespace = "Intelix"

        if self.service == 'get':
            if self.data_type == 'domain':
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

                predicate = "Categories"
                value = "SEC_CATEGORY:{}|PROD_CATEGORY:{}".format(self.ic.securityCategory, self.ic.productivityCategory)

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

if __name__ == '__main__':
    SophosIntelixAnalyzer().run()
