#!/usr/bin/env python3
from urllib.parse import quote

import requests
from cortexutils.analyzer import Analyzer

INDICATOR_TYPES = {
    'ip': 'ip',
    'domain': 'domain',
    'fqdn': 'domain',
    'url': 'url',
    'hash': 'hash',
    'mail': 'email',
    'filename': 'file',
}
BAND_LEVELS = {'critical': 'malicious', 'high': 'suspicious'}


class OffSeqRadarAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.base_url = self.get_param('config.base_url', 'https://radar.offseq.com/api/v1').rstrip('/')
        self.headers = {
            'X-API-Key': self.get_param('config.key', None, 'Missing OffSeq Radar API key'),
            'Accept': 'application/json',
        }

    def call(self, method, path, **kwargs):
        try:
            response = requests.request(method, self.base_url + path, headers=self.headers, timeout=30, **kwargs)
        except requests.exceptions.RequestException as e:
            self.error('Error while contacting OffSeq Radar: {}'.format(e))
        if response.status_code == 404:
            return None
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code != 200:
            self.error('OffSeq Radar error ({}): {}'.format(
                response.status_code, body.get('message') or body.get('error') or response.text[:200]))
        return body.get('data')

    def lookup_cve(self):
        cve = self.get_data().strip().upper()
        threat = self.call('GET', '/threats/slug/' + quote(cve.lower()))
        if not threat:
            return {'found': False, 'cve': cve}
        return {
            'found': True,
            'cve': cve,
            'url': 'https://radar.offseq.com/threat/' + threat.get('slug', cve.lower()),
            'threat': threat,
        }

    def check_indicator(self):
        value = self.get_data().strip()
        data = self.call('POST', '/threats/check-iocs', json={
            'indicators': [{'type': INDICATOR_TYPES[self.data_type], 'value': value}],
        }) or {}
        matches = next(iter(data.get('results') or []), {}).get('matches', [])
        exact = any(
            indicator.get('value', '').lower() == value.lower()
            for match in matches for indicator in match.get('matchingIndicators', [])
        )
        return {'indicator': value, 'exact': exact, 'matches': matches}

    def summary(self, raw):
        namespace = 'OffSeqRadar'
        if self.service == 'ioc':
            count = len(raw.get('matches', []))
            level = 'suspicious' if raw.get('exact') else 'info'
            return {'taxonomies': [self.build_taxonomy(level, namespace, 'Threats', count)]}

        if not raw.get('found'):
            return {'taxonomies': [self.build_taxonomy('info', namespace, 'CVE', 'Not found')]}
        threat = raw['threat']
        priority = threat.get('priority') or {}
        band = priority.get('band')
        taxonomies = [self.build_taxonomy(
            BAND_LEVELS.get(band, 'info'), namespace, 'Priority',
            '{} ({})'.format(band, priority.get('score')) if band else 'N/A')]
        if threat.get('kev'):
            taxonomies.append(self.build_taxonomy('malicious', namespace, 'KEV', 'listed'))
        epss = (threat.get('epss') or {}).get('score')
        if isinstance(epss, (int, float)):
            taxonomies.append(self.build_taxonomy(
                'suspicious' if epss >= 0.1 else 'info', namespace, 'EPSS', round(epss, 3)))
        maturity = (threat.get('exploit') or {}).get('maturity')
        if maturity:
            taxonomies.append(self.build_taxonomy('suspicious', namespace, 'Exploit', maturity))
        return {'taxonomies': taxonomies}

    def run(self):
        if self.service == 'cve' and self.data_type == 'cve':
            self.report(self.lookup_cve())
        elif self.service == 'ioc' and self.data_type in INDICATOR_TYPES:
            self.report(self.check_indicator())
        else:
            self.error('Data type {} is not supported by this flavor'.format(self.data_type))


if __name__ == '__main__':
    OffSeqRadarAnalyzer().run()
