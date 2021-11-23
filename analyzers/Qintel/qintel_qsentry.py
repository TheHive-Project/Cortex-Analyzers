#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer

from qintel_helper import search_qsentry


class Qintel(Analyzer):

    VERSION = '1.0'

    def __init__(self):
        Analyzer.__init__(self)
        self.token = self.get_param('config.token', None, 'Missing API Key')
        self.remote = self.get_param('config.remote', None)

    def _enrich(self, data):

        kwargs = {
            'token': self.token,
            'user_agent': f'cortex/{self.VERSION}'
        }

        try:
            return search_qsentry(data, **kwargs)
        except Exception as e:
            self.error(f'Qintel API request failed: {str(e)}')

    def summary(self, raw):
        taxonomies = []
        ns = 'Qintel'

        for tag in self.res.get('tags', []):
            level = 'suspicious'

            if tag == 'criminal':
                level = 'malicious'

            tax = self.build_taxonomy(level, ns, 'tag', tag)
            taxonomies.append(tax)

        return {'taxonomies': taxonomies}

    def run(self):
        if self.data_type not in ['ip']:
            self.error(f'Unsupported data type: {self.data_type}')

        data = self.getData()
        self.res = self._enrich(data)

        self.report({
            'Qintel': self.res
        })


if __name__ == '__main__':
    Qintel().run()
