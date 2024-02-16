#!/usr/bin/env python3
# encoding: utf-8
import json
import requests

from cortexutils.analyzer import Analyzer


class C1fQueryAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.cif_key = self.get_param('config.key', None, 'Missing C1fApp API key')
        self.api_url = self.get_param('config.url', None, 'Missing API URL')

    @staticmethod
    def _getheaders():
        return {
            'user-agent': "cortex-analyzer-v1.0",
            'Accept': 'application/json'
        }

    @staticmethod
    def cleanup(return_data):

        response = dict()
        assessments = []
        feed_labels = []
        descriptions = []
        asns = []
        asn_descs = []
        countries = []
        domains = []
        ip_addresses = []

        found = False
        count = 0

        for entry in return_data:
            found = True
            assessments.append(entry.get('assessment'))
            feed_labels.append(entry.get('feed_label'))
            descriptions.append(entry.get('description'))
            asns.append(entry.get('asn'))
            asn_descs.append(entry.get('asn_desc'))
            countries.append(entry.get('country'))
            domains.append(entry.get('domain'))
            domains.append(entry.get('fqdn'))
            dga_indication = entry.get('dga')

            if len(list(entry.get('ip_address'))) > 0:
                for ip in entry.get('ip_address'):
                    ip_addresses.append(ip)
            else:
                ip_addresses.append(entry.get('ip_address'))

        response['assessment'] = list(set(assessments[0]))
        response['feed_label'] = list(set(feed_labels[0]))
        response['description'] = list(set(descriptions[0]))
        response['asn'] = list(set(asns[0]))
        response['asn_desc'] = list(set(asn_descs[0]))
        response['country'] = list(set(countries[0]))
        response['domains'] = list(set(domains[0]))
        response['ip_addresses'] = list(set(ip_addresses))
        response['dga'] = dga_indication
        response['found'] = found
        response['count'] = len(return_data)

        return response

    def c1f_query(self, data):
        headers = self._getheaders()
        results = dict()

        try:
            _session = requests.Session()

            payload = {'key': self.cif_key,
                       'format': 'json',
                       'backend': 'es',
                       'request': data
                       }

            _query = _session.post(self.api_url, headers=headers,
                                   data=json.dumps(payload))
            if _query.status_code == 200:
                if _query.text == "[]":
                    return dict()
                else:
                    return self.cleanup(_query.json())
            else:
                self.error('API Access error: %s' % _query.text)

        except Exception as e:
            self.error('API Request error')

        return results

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "C1fApp"
        predicate = "Assessment"
        for a in raw["assessment"]:
            if a in ["whitelist"]:
                level = "safe"
            elif a in ["suspicious"]:
                level = "suspicious"
            elif a in ["phishing", "malware", "botnet", "Exploit"]:
                level = "malicious"
            value = "{}".format(a)
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'url' or self.data_type == 'domain' \
                or self.data_type == 'ip':
            data = self.get_param('data', None, 'Data is missing')

            rep = self.c1f_query(data)
            self.report(rep)

        else:
            self.error('Invalid data type')


if __name__ == '__main__':
    C1fQueryAnalyzer().run()
