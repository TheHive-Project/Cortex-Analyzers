#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer

from qintel_helper import search_qwatch


class QWatch(Analyzer):

    VERSION = '1.0'

    def __init__(self):
        Analyzer.__init__(self)
        self.client_id = self.get_param('config.access_id', None,
                                        'Missing Crosslink ID')
        self.client_secret = self.get_param('config.access_secret', None,
                                            'Missing Crosslink Secret')
        self.remote = self.get_param('config.remote', None)

    def _search(self, data):

        kwargs = {
            'remote': self.remote,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'user_agent': f'cortex/{self.VERSION}',
            'params': {
                'meta[total]': True,
                'stats': True
            }
        }

        try:
            return search_qwatch(data, self.data_type, 'exposures', **kwargs)
        except RuntimeWarning:
            pass
        except Exception as e:
            self.error(f'Qintel API: request failed, {str(e)}')

    def summary(self, raw):
        taxonomies = []
        ns = 'Qintel'
        level = 'info'

        count = self.res['meta']['total']
        taxonomies.append(self.build_taxonomy(level, ns,
                                              'CredentialCount', count))

        return {'taxonomies': taxonomies}

    def run(self):
        if self.data_type not in ['domain', 'mail']:
            self.error('Unsupported data type')

        if self.data_type == 'mail':
            self.data_type = 'email'

        data = self.getData()
        self.res = self._search(data)

        self.report({
            'Qintel_QWatch': self.res
        })


if __name__ == '__main__':
    QWatch().run()
