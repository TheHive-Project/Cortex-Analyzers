#!/usr/bin/env python3

from cortexutils.analyzer import Analyzer
from crowdsec_api import Crowdsec
from datetime import datetime


class CrowdsecAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.crowdsec_key = self.get_param("config.api_key", None, "Missing Crowdsec API key")
        self.crowdsec_client = None
        self.verbose_taxonomies = self.get_param("config.verbose_taxonomies", False)
        self.polling_interval = self.get_param("config.polling_interval", 60)

    def summary(self, raw):
        taxonomies = []
        namespace = "Crowdsec"
        levelinfo = "info"
        levelorange = "suspicious"
        levelgreen = "safe"

        if 'as_name' in raw:
                taxonomies.append(self.build_taxonomy(levelinfo, namespace, 'ASN', raw['as_name']))

        if 'ip_range_score' in raw:
                taxonomies.append(self.build_taxonomy(levelinfo, namespace, 'Score', raw['ip_range_score']))

        if 'history' in raw:
                taxonomies.append(self.build_taxonomy(levelinfo, namespace, 'LastSeen', raw['history']['last_seen']))

        if 'attack_details' in raw:
                for attack in raw['attack_details'] :
                    taxonomies.append(self.build_taxonomy(levelorange, namespace, 'Attack', attack['name']))
                    
        if len(taxonomies) == 0:
                taxonomies.append(self.build_taxonomy(levelgreen, namespace, 'Threat', 'Not found'))

        ### uncomment for full taxonomies report
        #if raw['attack_details']:
        #        for attackdetails in raw['attack_details'] :
        #            taxonomies.append(self.build_taxonomy(levelorange, namespace, 'Attack_details', attackdetails['name']))

        return {"taxonomies": taxonomies}


    def run(self):
        Analyzer.run(self)
        try:
            self.crowdsec_client = Crowdsec(self.crowdsec_key)
            data = self.get_param("data", None, "Data is missing")
            results = self.crowdsec_client.summary(data, self.data_type)
                
            self.report(results)

        except Exception:
            pass


if __name__ == "__main__":
    CrowdsecAnalyzer().run()

