#!/usr/bin/env python3
# encoding: utf-8
import requests
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

from cortexutils.analyzer import Analyzer


class IBMXForceAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            'config.service', None, 'Service parameter is missing')
        self.url = self.get_param('config.url', None, 'Missing API url')
        if self.url:
            self.url = self.url.rstrip('/')
        self.key = self.get_param('config.key', None, 'Missing API key')
        self.pwd = self.get_param('config.pwd', None, 'Missing API password')
        self.verify = self.get_param('config.verify', True)
        if not self.verify:
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        self.proxies = self.get_param('config.proxy', None)

    def parse_data(self, date):
        try:
            date = datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            date = datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ")
        return date.strftime("%Y-%m-%d")

    def cleanup(self, ip_data={}, malware_data={}, dns_data={}):
        response = {
            'malware': [],
            'history': [],
            'dns': [],
            'cats': [],
            'families': [],
            'emails_info': [],
            'subjects_info': [],
            'score': None,
            'score_value': None,
            'score_nr': 0
        }

        if self.data_type == 'ip':
            score_value = ip_data.get('score', 0)
            score_nr = score_value
            cats = ip_data.get('cats', [])
            score = "%d [%d category(s)]" % (score_value, len(cats)) if len(cats) > 0 else score_value
            families = []

        elif self.data_type in ['domain', 'url']:
            score_value = ip_data.get('result', {}).get('score', 0)
            score_nr = score_value
            cats = ip_data.get('result', {}).get('cats', {})
            cats = [x for x in cats.keys()]
            score = "%d [%d category(s)]" % (score_value, len(cats)) if len(cats) > 0 else score_value
            families = []

        else:
            score_value = malware_data.get('malware', {}).get('risk', 'low')
            if score_value == 'low':
                score_nr = 1
            elif score_value == 'medium':
                score_nr = 5
            else:
                score_nr = 10

            families = malware_data.get('malware', {}).get('family', [])
            score = "%s [%d family(s)]" % (score_value, len(families)) if len(families) > 0 else score_value
            cats = []

        response['score_value'] = score_value
        response['cats'] = cats
        response['score'] = score
        response['score_nr'] = score_nr
        response['families'] = families

        for hist in ip_data.get('history', []):
            tmp = {}
            tmp['day'] = self.parse_data(hist['created'])
            tmp['country'] = hist.get('geo', {}).get('country', None)
            tmp['ip'] = hist.get('ip', None)
            tmp['score'] = hist.get('score', 0)
            tmp['ans'] = hist.get('asns', {})
            tmp['cats'] = [{'name': x, 'score': y} for (x, y) in hist.get('cats', {}).items()]
            tmp['deleted'] = hist.get('deleted', False)
            response['history'].append(tmp)
        response['history'].reverse()

        if self.data_type != 'hash':
            response['malware'] = malware_data.get('malware', [])
        else:
            origins = malware_data.get('malware', {}).get('origins', [])
            emails = origins.get('emails', {}).get('rows', [])
            subjects = origins.get('subjects', {}).get('rows', [])
            response['emails_info'] = [
                (x['domain'], x['ip'], x['uri'], self.parse_data(x['lastseen'])) for x in emails]
            response['subjects_info'] = [
                (x['subject'], x['count'], x['ips'], self.parse_data(x['lastseen'])) for x in subjects]

        for x in dns_data.get('Passive', {}).get('records', []):
            response['dns'].append(
                (self.parse_data(x["first"]), self.parse_data(x["last"]), x["value"]))

        if 'RDNS' in dns_data.keys():
            response['dns'].append(
                ("", "", ",".join([x for x in dns_data['RDNS']])))

        return response

    def ip_query(self, data):
        results = dict()

        try:
            _session = requests.Session()
            _session.auth = (self.key, self.pwd)

            _query_ip = _session.get('%s/ipr/%s' % (self.url, data), proxies=self.proxies, verify=self.verify)
            _query_malware = _session.get(
                '%s/ipr/malware/%s' % (self.url, data), proxies=self.proxies, verify=self.verify)
            _query_info = _session.get('%s/resolve/%s' % (self.url, data), proxies=self.proxies, verify=self.verify)

            ip_data = _query_ip.json() if _query_ip.status_code == 200 else {}
            malware_data = _query_malware.json() if _query_malware.status_code == 200 else {}
            dns_data = _query_info.json() if _query_info.status_code == 200 else {}
            if ip_data or malware_data or dns_data:
                return self.cleanup(ip_data=ip_data, malware_data=malware_data, dns_data=dns_data)
            else:
                self.error('API Access error')

        except Exception as e:
            self.error("OS error: {0}".format(e))

        return results

    def domain_query(self, data):
        results = dict()

        try:
            _session = requests.Session()
            _session.auth = (self.key, self.pwd)

            _query_url = _session.get('%s/url/%s' % (self.url, data), proxies=self.proxies, verify=self.verify)
            _query_malware = _session.get(
                '%s/url/malware/%s' % (self.url, data), proxies=self.proxies, verify=self.verify)
            _query_info = _session.get('%s/resolve/%s' % (self.url, data), proxies=self.proxies, verify=self.verify)

            url_data = _query_url.json() if _query_url.status_code == 200 else {}
            malware_data = _query_malware.json() if _query_malware.status_code == 200 else {}
            dns_data = _query_info.json() if _query_info.status_code == 200 else {}
            if url_data or malware_data or dns_data:
                return self.cleanup(ip_data=url_data, malware_data=malware_data, dns_data=dns_data)
            else:
                self.error('API Access error')

        except Exception as e:
            self.error("OS error: {0}".format(e))

        return results

    def malware_query(self, data):
        results = dict()

        try:
            _session = requests.Session()
            _session.auth = (self.key, self.pwd)

            _query_malware = _session.get(
                '%s/malware/%s' % (self.url, data), proxies=self.proxies, verify=self.verify)

            if _query_malware.status_code == 200:
                return self.cleanup(malware_data=_query_malware.json())
            else:
                self.error('API Access error')

        except Exception as e:
            self.error("OS error: {0}".format(e))

        return results

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "IBMXForce"
        predicate = "Score"
        score_value = raw['score_value']
        score = raw['score']

        if score_value < 4 or score_value == 'low':
            level = "safe"
        elif score_value < 7 or score_value == 'medium':
            level = "suspicious"
        elif score_value >= 7 or score_value == 'high':
            level = "malicious"

        #taxonomies.append(self.build_taxonomy(level, namespace, predicate, "{}".format(score)))
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, "{}".format(score)))


        return {"taxonomies": taxonomies}

    def run(self):

        if self.service == 'query':
            data = self.get_param('data', None, 'Data is missing')
            if self.data_type == 'ip':
                rep = self.ip_query(data)
                self.report(rep)
            elif self.data_type in ['domain', 'url']:
                rep = self.domain_query(data)
                self.report(rep)
            elif self.data_type == 'hash':
                rep = self.malware_query(data)
                self.report(rep)
            else:
                self.error('Invalid data type')
        else:
            self.error('Invalid service')


if __name__ == '__main__':
    IBMXForceAnalyzer().run()
