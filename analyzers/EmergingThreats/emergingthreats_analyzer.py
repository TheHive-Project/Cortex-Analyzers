#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer

import hashlib
import requests
import time

RED_CATEGORIES = [
    "Blackhole", "Bot", "Brute_Forcer", "CnC",
    "Compromised", "DDoSAttacker", "DDoSTarget",
    "DriveBySrc", "Drop", "EXE_Source",
    "FakeAV", "Mobile_CnC", "Mobile_Spyware_CnC",
    "P2PCnC", "Scanner", "Spam", "SpywareCnC"
]

YELLOW_CATEGORIES = [
    "AbusedTLD", "Bitcoin_Related", "ChatServer",
    "DynDNS", "IPCheck", "OnlineGaming", "P2P",
    "Parking", "Proxy", "RemoteAccessService",
    "SelfSignedSSL", "Skype_SuperNode", "TorNode",
    "Undesirable", "VPN"
]

GREEN_CATEGORIES = [
    "Utility"
]


class EmergingThreatsAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.apikey = self.get_param('config.key', None, 'EmergingThreats apikey is missing')
        self.session = requests.Session()
        self.session.headers.update({"Authorization": self.apikey})

    def summary(self, raw):
        taxonomies = []
        namespace = "ET"

        if self.data_type in ['domain', 'ip'] and raw['reputation'] not in ["-", "Error"]:
            for x in raw["reputation"]:
                value = "%s=%d" % (x['category'], x['score'])
                if x['category'] in RED_CATEGORIES and x['score'] >= 70:
                    level = "malicious"
                elif (70 <= x['score'] < 100 and x['category'] in RED_CATEGORIES) or (
                        x['score'] >= 100 and x['category'] in YELLOW_CATEGORIES):
                    level = "suspicious"
                else:
                    level = "safe"
                taxonomies.append(self.build_taxonomy(level, namespace, "%s-info" % self.data_type, value))
        elif self.data_type == 'hash' and raw['events'] not in ["-", "Error"]:
            value = str(len(raw['events'])) + " signatures"
            taxonomies.append(self.build_taxonomy("malicious", namespace, 'malware-info', value))

        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)
        info = {}
        try:
            if self.data_type != 'file':
                object_name = self.get_data()

            if self.data_type in ['domain', 'fqdn']:
                url = "https://api.emergingthreats.net/v1/domains/"
                features = {'reputation', 'urls', 'samples', 'ips', 'events', 'nameservers', 'whois', 'geoloc'}

            elif self.data_type == 'ip':
                url = "https://api.emergingthreats.net/v1/ips/"
                features = {'reputation', 'urls', 'samples', 'domains', 'events', 'geoloc'}

            elif self.data_type == 'hash':
                url = "https://api.emergingthreats.net/v1/samples/"
                features = {'', 'connections', 'dns', 'http', 'events'}

            elif self.data_type == 'file':
                url = "https://api.emergingthreats.net/v1/samples/"
                features = {'', 'connections', 'dns', 'http', 'events'}
                hashes = self.get_param('attachment.hashes', None)
                if hashes is None:
                    filepath = self.get_param('file', None, 'File is missing')
                    object_name = hashlib.md5(open(filepath, 'r').read()).hexdigest()
                else:
                    # find MD5 hash
                    object_name = next(h for h in hashes if len(h) == 32)

            else:
                self.error('Invalid data type !')

            for feature in features:
                end = '/' if feature else ''
                time.sleep(1)
                r = self.session.get(url + object_name + end + feature)
                if feature == '':
                    feature = 'main'
                r_json = r.json()
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
