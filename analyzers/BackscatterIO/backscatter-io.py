#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from backscatter import Backscatter
from collections import defaultdict, OrderedDict
from cortexutils.analyzer import Analyzer


class BackscatterAnalyzer(Analyzer):

    """
    Backscatter.io API docs: https://backscatter.io/developers
    """

    def __init__(self):
        """Setup the Backscatter object."""
        Analyzer.__init__(self)
        self.api_key = self.get_param('config.key', None, 'No Backscatter.io API key provided.')
        self.proxies = {
            "https" : self.get_param("config.proxy_https"),
            "http" : self.get_param("config.proxy_http")
        }
        kwargs = {'api_key': self.api_key, 'headers': {'X-Integration': 'TheHive'}}
        if self.proxies['https'] or self.proxies['http']:
            kwargs.update({'proxies': self.proxies})
        self.bs = Backscatter(**kwargs)
        self.service = self.get_param('config.service', None, 'Backscatter service is missing')

    def run(self):
        """Run the process to get observation data from Backscatter.io."""
        kwargs = {'query': self.get_data()}
        if self.data_type == "ip":
            kwargs.update({'query_type': 'ip'})
        elif self.data_type == "network":
            kwargs.update({'query_type': 'network'})
        elif self.data_type == 'autonomous-system':
            kwargs.update({'query_type': 'asn'})
        elif self.data_type == 'port':
            kwargs.update({'query_type': 'port'})
        else:
            self.notSupported()
            return False

        if self.service == 'observations':
            response = self.bs.get_observations(**kwargs)
            self.report(response)
        elif self.service == 'enrichment':
            response = self.bs.enrich(**kwargs)
            self.report(response)
        else:
            self.report({'error': 'Invalid service defined.'})

    def summary(self, raw):
        """Use the Backscatter.io summary data to create a view."""
        taxonomies = list()
        level = 'info'
        namespace = 'Backscatter.io'

        if self.service == 'observations':
            summary = raw.get('results', dict()).get('summary', dict())
            taxonomies = taxonomies + [
                self.build_taxonomy(level, namespace, 'Observations', summary.get('observations_count', 0)),
                self.build_taxonomy(level, namespace, 'IP Addresses', summary.get('ip_address_count', 0)),
                self.build_taxonomy(level, namespace, 'Networks', summary.get('network_count', 0)),
                self.build_taxonomy(level, namespace, 'AS', summary.get('autonomous_system_count', 0)),
                self.build_taxonomy(level, namespace, 'Ports', summary.get('port_count', 0)),
                self.build_taxonomy(level, namespace, 'Protocols', summary.get('protocol_count', 0))
            ]
        elif self.service == 'enrichment':
            summary = raw.get('results', dict())
            if self.data_type == 'ip':
                taxonomies = taxonomies + [
                    self.build_taxonomy(level, namespace, 'Network', summary.get('network')),
                    self.build_taxonomy(level, namespace, 'Network Broadcast', summary.get('network_broadcast')),
                    self.build_taxonomy(level, namespace, 'Network Size', summary.get('network_size')),
                    self.build_taxonomy(level, namespace, 'Country', summary.get('country_name')),
                    self.build_taxonomy(level, namespace, 'AS Number', summary.get('as_num')),
                    self.build_taxonomy(level, namespace, 'AS Name', summary.get('as_name')),
                ]
            elif self.data_type == 'network':
                taxonomies = taxonomies + [
                    self.build_taxonomy(level, namespace, 'Network Size', summary.get('network_size'))
                ]
            elif self.data_type == 'autonomous-system':
                taxonomies = taxonomies + [
                    self.build_taxonomy(level, namespace, 'Prefix Count', summary.get('prefix_count')),
                    self.build_taxonomy(level, namespace, 'AS Number', summary.get('as_num')),
                    self.build_taxonomy(level, namespace, 'AS Name', summary.get('as_name'))
                ]
            elif self.data_type == 'port':
                for result in raw.get('results', list()):
                    display = "%s (%s)" % (result.get('service'), result.get('protocol'))
                    taxonomies.append(self.build_taxonomy(level, namespace, 'Service', display))
            else:
                pass
        else:
            pass
        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    BackscatterAnalyzer().run()
