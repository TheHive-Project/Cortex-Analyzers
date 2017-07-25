#!/usr/bin/env python
# encoding: utf-8

from cortexutils.analyzer import Analyzer

import requests
import time
import tldextract

class EmergingThreatsAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'EmergingThreats service is missing')
        self.apikey = self.get_param('config.key', None, 'EmergingThreats apikey is missing')
        self.session = requests.Session()
        self.session.headers.update({"Authorization": self.apikey})

    def summary(self, raw):
        taxonomies = []
        level = "safe"
        namespace = "ET"
        predicate = self.service

        result = {
            'service': self.service,
            'dataType': self.data_type
        }
        
        if predicate in ['domain-info', 'ip-info']:
            value = "|".join([x['category'] + "=" + str(x['score']) for x in result["reputation"] if result["reputation"] != '-'])
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
            
        result.update({"taxonomies":taxonomies})
        return result

    def run(self):
        Analyzer.run(self)
        info = {}
        try:
            objectName = self.getData()
            if self.service == 'domain-info':
                self.data_type = 'domain'
                objectName = tldextract.extract(objectName).registered_domain
                url = "https://api.emergingthreats.net/v1/domains/"
                features = {'reputation', 'urls', 'samples', 'ips', 'events', 'nameservers', 'whois', 'geoloc'}

            elif self.service == 'ip-info':
                self.data_type = 'ip'
                url = "https://api.emergingthreats.net/v1/ips/"
                features = {'reputation', 'urls', 'samples', 'domains', 'events', 'geoloc'}

            elif self.service == 'malware-info':
                self.data_type = 'malware'
                url = "https://api.emergingthreats.net/v1/samples/"
                features = {'', 'connections', 'dns', 'events'}              
            else:
                self.error('Unknown EmergingThreats service')

            for feature in features:
                end = '/' if feature else ''
                r = self.session.get(url + objectName + end + feature)
                r_json= r.json()
                if r.status_code == 200 and r_json['response'] not in [{}, []]:
                    info[feature] = r_json['response']
                elif r.status_code != 200:
                    info[feature] = "Error"
                else:
                    info[feature] = "-"

            self.report(info)

        except Exception as e:
            self.unexpectedError(e)

if __name__ == '__main__':
    EmergingThreatsAnalyzer().run()
