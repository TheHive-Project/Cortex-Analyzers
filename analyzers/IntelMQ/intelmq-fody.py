#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from imqfody import IMQFody
from warnings import catch_warnings, simplefilter


class IntelmqFodyAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self._url = self.get_param('config.url', None, 'No URL given.')
        self._username = self.get_param('config.username', None, 'No username given.')
        self._password = self.get_param('config.password', None, 'No password given.')
        cert_check = self.get_param('config.cert_check', True)
        cert_path = self.get_param('config.cert_path', None)
        self.ssl_verify = cert_path if cert_path and cert_check else cert_check
        if not self.ssl_verify:
            with catch_warnings():
                simplefilter('ignore')
                self._client = IMQFody(
                    url=self._url,
                    username=self._username,
                    password=self._password,
                    sslverify=self.ssl_verify
                )
        else:
            self._client = IMQFody(
                url=self._url,
                username=self._username,
                password=self._password,
                sslverify=self.ssl_verify
            )
        self._service = self.get_param('config.service', None, 'No service given.')

    def _search_event_source(self):
        if self.data_type == 'ip':
            events = {
                'source': self._client.search_event({
                    'source-ip_is': self.get_data()
                })
            }
        elif self.data_type == 'fqdn':
            events = {
                'source': self._client.search_event({
                    'source-fqdn_icontains': self.get_data()
                })
            }
        else:
            self.error('Data type {} is currently not supported.'.format(self.data_type))
        return events

    def _search_event_destination(self):
        if self.data_type == 'ip':
            events = {
                'destination': self._client.search_event({
                    'destination-ip_is': self.get_data()
                })
            }
        elif self.data_type == 'fqdn':
            events = {
                'destination': self._client.search_event({
                    'destination-fqdn_icontains': self.get_data()
                })
            }
        else:
            self.error('Data type {} is currently not supported.'.format(self.data_type))
        return events

    def _search_contact_db(self):
        if self.data_type == 'ip':
            orgs = self._client.search_ip(self.get_data())
        elif self.data_type == 'domain' or self.data_type == 'fqdn':
            orgs = self._client.search_fqdn(self.get_data())
        elif self.data_type == 'autonomous-system':
            orgs = self._client.search_asn(self.get_data())
        else:
            self.error('Data type {} is currently not supported.'.format(self.data_type))
        self.report({
            'results': orgs
        })

    def run(self):
        with catch_warnings():
            if not self.ssl_verify:
                simplefilter('ignore')
            else:
                simplefilter('error')
            if self._service == 'eventSourceSearch':
                self._search_event_source()
            elif self._service == 'eventDestinationSearch':
                self._search_event_destination()
            elif self._service == 'contactDBSearch':
                self._search_contact_db()
            else:
                self.error('Service {} not supported by analyzer.'.format(self._service))


if __name__ == '__main__':
    IntelmqFodyAnalyzer().run()
