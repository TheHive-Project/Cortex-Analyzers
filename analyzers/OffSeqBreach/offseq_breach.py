#!/usr/bin/env python3
from urllib.parse import quote

import requests
from cortexutils.analyzer import Analyzer

CATEGORIES = ('employees', 'customers', 'third_parties')


class OffSeqBreachAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.base_url = self.get_param('config.base_url', 'https://breach.offseq.com/api/v1').rstrip('/')
        self.confirm_credit = self.get_param('config.confirm_credit', False)
        self.headers = {
            'X-API-Key': self.get_param('config.key', None, 'Missing OffSeq Breach API key'),
            'Accept': 'application/json',
        }

    def call(self, method, path, **kwargs):
        try:
            response = requests.request(method, self.base_url + path, headers=self.headers, timeout=60, **kwargs)
        except requests.exceptions.RequestException as e:
            self.error('Error while contacting OffSeq Breach: {}'.format(e))
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code == 200:
            return body
        if response.status_code == 404 and body.get('error_code') == 'no_data':
            return None
        if response.status_code == 402:
            self.error('OffSeq Breach daily lookup allowance used up; enable confirm_credit to spend pay-per-search credits')
        self.error('OffSeq Breach error ({}): {}'.format(
            response.status_code, body.get('error') or response.text[:200]))

    def search_domain(self):
        domain = self.get_data().strip().lower()
        params = {'light': 'true'}
        if self.confirm_credit:
            params['confirm_credit'] = 'true'
        data = self.call('GET', '/search/domain/' + quote(domain), params=params)
        if data is None:
            return {'domain': domain, 'found': False}
        counts = {c: data.get(c + '_compromised') or 0 for c in CATEGORIES}
        return {
            'domain': domain,
            'found': any(counts.values()),
            'counts': counts,
            'employee_passwords': data.get('employee_passwords'),
            'customer_passwords': data.get('customer_passwords'),
        }

    def search_email(self):
        email = self.get_data().strip().lower()
        body = {'email': email, 'page_size': 100}
        if self.confirm_credit:
            body['confirm_credit'] = True
        data = self.call('POST', '/search/email', json=body)
        return {
            'email': email,
            'found': bool(data.get('total')),
            'total': data.get('total', 0),
            'leaks': data.get('items', []),
        }

    def summary(self, raw):
        namespace = 'OffSeqBreach'
        if self.service == 'email':
            total = raw.get('total', 0)
            return {'taxonomies': [self.build_taxonomy(
                'malicious' if total else 'safe', namespace, 'Leaks', total)]}
        counts = raw.get('counts') or {}
        employees = counts.get('employees', 0)
        taxonomies = [self.build_taxonomy(
            'malicious' if employees else 'safe', namespace, 'Employees', employees)]
        for category, predicate in (('customers', 'Customers'), ('third_parties', 'ThirdParties')):
            if counts.get(category):
                taxonomies.append(self.build_taxonomy('suspicious', namespace, predicate, counts[category]))
        return {'taxonomies': taxonomies}

    def run(self):
        if self.service == 'domain' and self.data_type in ('domain', 'fqdn'):
            self.report(self.search_domain())
        elif self.service == 'email' and self.data_type == 'mail':
            self.report(self.search_email())
        else:
            self.error('Data type {} is not supported by this flavor'.format(self.data_type))


if __name__ == '__main__':
    OffSeqBreachAnalyzer().run()
