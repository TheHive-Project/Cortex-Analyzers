#!/usr/bin/env python
# encoding: utf-8
import os
import requests
import json
from cortexutils.analyzer import Analyzer
from urllib import quote_plus

requests.packages.urllib3.disable_warnings()


class CymonApi(object):

    def __init__(self, auth_token=None,
                                endpoint='https://cymon.io:443/api/nexus/v1'):
        self.endpoint = endpoint
        self.session = requests.Session()
        self.session.headers = {
            'content-type': 'application/json',
            'accept': 'application/json',
        }
        if auth_token:
            self.session.headers.update(
                         {'Authorization': 'Token {0}'.format(auth_token)})

    def get(self, method, params=None):
        r = self.session.get(self.endpoint + method, params=params)
        r.raise_for_status()
        return r

    def post(self, method, params, headers=None):
        r = self.session.post(self.endpoint + method, data=json.dumps(params),
                                                             headers=headers)
        r.raise_for_status()
        return r

    def ip_lookup(self, ip_addr):
        r = self.get('/ip/' + ip_addr)
        return r.json()

    def ip_events(self, ip_addr):
        r = self.get('/ip/' + ip_addr + '/events')
        return r.json()

    def ip_domains(self, ip_addr):
        r = self.get('/ip/' + ip_addr + '/domains')
        return r.json()

    def ip_urls(self, ip_addr):
        r = self.get('/ip/' + ip_addr + '/urls')
        return r.json()

    def domain_lookup(self, name):
        r = self.get('/domain/' + name)
        return r.json()

    def url_lookup(self, location):
        r = self.get('/url/' + quote_plus(location))
        return r.json()

    def ip_blacklist(self, tag, days=1, limit=10, offset=10):
        # supported tags: malware, botnet, spam, phishing, dnsbl, blacklist
        r = self.get('/blacklist/ip/' + tag + '/?days=%d' % (days) +
                                          '&limit=%d' % (limit) +
                                          '&offset=%d' % (offset))
        return r.json()

    def domain_blacklist(self, tag, days=1, limit=15, offset=10):
        # supported tags: malware, botnet, spam, phishing, dnsbl, blacklist
        r = self.get('/blacklist/domain/' + tag + '/?days=%d' % (days) +
                                          '&limit=%d' % (limit) +
                                          '&offset=%d' % (offset))
        return r.json()


class CymonEngine(object):

    def __init__(self, key):

        self.cymon_cat = ['malware',
                     'botnet',
                     'spam',
                     'phishing',
                     'malicious activity',
                     'blacklist',
                     'dnsbl']


        self.api = CymonApi(key)

    def loadSetting(self, filepath):

        with open(filepath, 'rb') as f:
            d = json.loads(f.read())
            return d

    def search(self, ipaddr):

        d = {'Founds': {},
              'stats': {}
             }
        total = 0
        modo = 'ip_events'
        func = getattr(self.api, modo)
        req = func(ipaddr)

        d['Clear'] = True

        for item in self.cymon_cat:
            tag_found = False
            for elem in req['results']:
                if item in elem['tag']:
                    tag_found = True
            if tag_found:
                d['Clear'] = False

                s = self.api.ip_lookup(ipaddr)['sources']

                if 'malicious' in item:
                    d['stats']['total_malicious'] = len(s)
                    d['malicious_activity'] = s
                    d['Founds']['malicious_activity'] = tag_found
                else:
                    d['Founds'][item] = tag_found
                    d['stats']['total_' + item] = len(s)
                    d[item] = s

                total = total + len(s)

            else:
                if 'malicious' in item:
                    d['stats']['total_malicious'] = 0
                    d['Founds']['malicious_activity'] = tag_found
                else:
                    d['stats']['total_' + item] = 0
                    d['Founds'][item] = tag_found

        d['permalink'] = 'https://cymon.io/' + ipaddr
        d['Success'] = True
        d['total'] = total

        return d


class CymonAnalyzer(Analyzer):

    def __init__(self):

        Analyzer.__init__(self)

        self.service = self.getParam('config.service', None,
                                     'Cymon service is missing')
        self.key = self.getParam('config.key', None,
                                 'Cymon API key is missing')
        self.con = CymonEngine(self.key)

    def summary(self, raw_report):

        taxonomy = {"level": "malicious", "namespace": "Cymon.io", "predicate": "Analisis", "value": 0}
        taxonomies = []
        level = "malicious"
        namespace = "Cymon.io"
        predicate = "Report"
        value = "\"\""

        for elm in raw_report["Founds"]:
            if raw_report["Founds"][elm]:
                if elm in ["spam", "blacklist", "phishing", "dnsbl"]:
                    level = 'suspicious'
                value = "{}".format(elm)
                taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        if raw_report["Clear"]:
                value = "{}".format("Clear")
                taxonomies.append(self.build_taxonomy("info", namespace, predicate, value))

        result = {
            'Malware': raw_report['Founds']['malware'],
            'Blacklist': raw_report['Founds']['blacklist'],
            'MaliciousActivity': raw_report['Founds']['malicious_activity'],
            'Dns_blacklist': raw_report['Founds']['dnsbl'],
            'Spam': raw_report['Founds']['spam'],
            'Phishing': raw_report['Founds']['phishing'],
            'Botnet': raw_report['Founds']['botnet'],
            'Source_link': raw_report['permalink'],
            'count': raw_report['total'],
            'stats': raw_report['stats'],
            'taxonomies':taxonomies
            }
        return result

    def artifacts(self, raw_report):

        result = []

        if self.service == 'Check_IP':
            pass

        return result

    def run(self):

        Analyzer.run(self)

        data = self.get_data()

        try:
            if self.service == 'Check_IP':

                if self.data_type == 'ip':

                    result = self.con.search(data)
                    self.report(result)

            else:
                self.notSupported()
        except ValueError as e:
                self.error('Invalid IP address')
        except Exception as e:
            self.unexpectedError(type(e))

if __name__ == '__main__':
    CymonAnalyzer().run()