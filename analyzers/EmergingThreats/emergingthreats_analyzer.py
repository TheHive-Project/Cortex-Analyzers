#!/usr/bin/env python
# encoding: utf-8

from cortexutils.analyzer import Analyzer

import requests
import time
import tldextract

RED_CATEGORIES = [
    "Blackhole", "Bot", "Brute_Forcer", "CnC", 
    "Compromised", "DDoSAttacker", "DDoSTarget", 
    "DriveBySrc", "Drop", "EXE_Source", 
    "FakeAV", "Mobile_CnC", "Mobile_Spyware_CnC", 
    "P2PCnC", "Scanner", "Spam", "SpywareCnC"
]

YELLOW_CATEGORIES = [
    "AbusedTLD", "Bitcoin_Related", "ChatServer",
    "DynDNS",  "IPCheck", "OnlineGaming", "P2P", 
    "Parking", "Proxy", "RemoteAccessService",
    "SelfSignedSSL", "Skype_SuperNode", "TorNode", 
    "Undesirable",  "VPN"
]

GREEN_CATEGORIES = [
    "Utility"
]

class EmergingThreatsAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'EmergingThreats service is missing')
        self.apikey = self.get_param('config.key', None, 'EmergingThreats apikey is missing')
        self.session = requests.Session()
        self.session.headers.update({"Authorization": self.apikey})

    def summary(self, raw):
        taxonomies = []
        namespace = "ET"
        predicate = self.service
        
        if predicate in ['domain-info', 'ip-info'] and raw['reputation'] != "-":
            for x in raw["reputation"]:
                value = "%s=%d" % (x['category'], x['score'])
                if x['category'] in RED_CATEGORIES and x['score'] >= 70:
                    level = "malicious"
                elif (40 <= x['score'] < 70 and x['category'] in RED_CATEGORIES) or (x['score'] >= 70 and x['category'] in YELLOW_CATEGORIES):
                    level = "suspicious"
                else:
                    level = "safe"
                taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
            
        return {"taxonomies":taxonomies}

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
