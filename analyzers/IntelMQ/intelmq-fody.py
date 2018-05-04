#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from imqfody import IMQFody


class IntelmqFodyAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self._url = self.get_param('config.url', None, 'No URL given.')
        self._username = self.get_param('config.username', None, 'No username given.')
        self._password = self.get_param('config.password', None, 'No password given.')
        self._client = IMQFody(
            url=self._url,
            username=self._username,
            password=self._password
        )

    def run(self):
        if self.data_type == 'ip':
            events = {
                'destination': self._client.search_event({
                    'destination-ip_is': self.get_data()
                }),
                'source': self._client.search_event({
                    'source-ip_is': self.get_data()
                })
            }
        elif self.data_type == 'fqdn' or self.data_type == 'domain':
            events = {
                'destination': self._client.search_event({
                    'destination-fqdn_icontains': self.get_data()
                }),
                'source': self._client.search_event({
                    'source-fqdn_icontains': self.get_data()
                })
            }
        else:
            self.error('Data type {} is currently not supported.'.format(self.data_type))
        self.report({
            'results': events
        })


if __name__ == '__main__':
    IntelmqFodyAnalyzer().run()
