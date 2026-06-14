#!/usr/bin/env python3
import requests
from cortexutils.analyzer import Analyzer


class OpenCVEAnalyzer(Analyzer):
    """Enrich a CVE observable with data from OpenCVE (https://www.opencve.io)."""

    def __init__(self):
        Analyzer.__init__(self)
        self.token = self.get_param('config.token', None, 'Missing OpenCVE API token')
        base_url = self.get_param('config.base_url', 'https://app.opencve.io/api')
        self.base_url = base_url.rstrip('/')
        self.proxies = self.get_param('config.proxy', None)

    @staticmethod
    def _best_cvss(metrics):
        """Return (score, vector, version) from the most recent CVSS metric available."""
        for version, key in (('3.1', 'cvssV3_1'), ('4.0', 'cvssV4_0'),
                             ('3.0', 'cvssV3_0'), ('2.0', 'cvssV2_0')):
            data = (metrics.get(key) or {}).get('data') or {}
            score = data.get('score')
            if isinstance(score, (int, float)):
                return score, data.get('vector'), version
        return None, None, None

    def summary(self, raw):
        taxonomies = []
        namespace = 'OpenCVE'

        if not raw.get('found', False):
            taxonomies.append(self.build_taxonomy('info', namespace, 'CVE', 'Not found'))
            return {'taxonomies': taxonomies}

        metrics = raw.get('metrics') or {}
        score, _, _ = self._best_cvss(metrics)
        kev = bool((metrics.get('kev') or {}).get('data'))

        if kev or (score is not None and score >= 9.0):
            level = 'malicious'
        elif score is not None and score >= 4.0:
            level = 'suspicious'
        else:
            level = 'info'

        taxonomies.append(self.build_taxonomy(
            level, namespace, 'CVSS', score if score is not None else 'N/A'))
        if kev:
            taxonomies.append(self.build_taxonomy('malicious', namespace, 'KEV', 'CISA'))
        return {'taxonomies': taxonomies}

    def run(self):
        if self.data_type != 'cve':
            self.error('OpenCVE analyzer only supports the cve data type')

        cve_id = self.get_param('data', None, 'Data is missing').strip().upper()
        url = '{}/cve/{}'.format(self.base_url, cve_id)
        headers = {
            'Authorization': 'Bearer {}'.format(self.token),
            'Accept': 'application/json',
        }

        try:
            response = requests.get(url, headers=headers, proxies=self.proxies, timeout=30)
        except requests.exceptions.RequestException as e:
            self.error('Error while contacting OpenCVE: {}'.format(e))

        if response.status_code == 401:
            self.error('OpenCVE authentication failed: check the API token')
        if response.status_code == 404:
            self.report({'found': False, 'cve_id': cve_id})
            return
        if response.status_code != 200:
            self.error('Unexpected OpenCVE response ({}): {}'.format(
                response.status_code, response.text[:200]))

        data = response.json()
        data['found'] = True

        # OpenCVE returns vendors as a flat list mixing "vendor" and
        # "vendor$PRODUCT$product" entries; split them for a readable report.
        vendors = set()
        products = []
        for entry in data.get('vendors', []) or []:
            if '$PRODUCT$' in entry:
                vendor, product = entry.split('$PRODUCT$', 1)
                vendors.add(vendor)
                products.append({'vendor': vendor, 'product': product.replace('\\', '')})
            else:
                vendors.add(entry)
        data['vendors_list'] = sorted(vendors)
        data['products'] = products

        self.report(data)


if __name__ == '__main__':
    OpenCVEAnalyzer().run()
