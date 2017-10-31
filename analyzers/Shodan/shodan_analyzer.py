#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.analyzer import Analyzer
from shodan_api import ShodanAPIPublic


class ShodanAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam('config.service', None, 'Service parameter is missing')
        self.shodan_key = self.getParam('config.key', None, 'Missing Shodan API key')
        self.shodan_client = None
        self.polling_interval = self.getParam('config.polling_interval', 60)

    def summary(self, raw):

        taxonomy = {"level": "info", "namespace": "Shodan", "predicate": "Location", "value": 0}
        taxonomies = []
        level = "info"
        namespace = "Shodan"
        predicate = "Location"
        if self.service == 'host':
            if 'country_name' in raw['host']:
                value = raw['host']['country_name']
                taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
            if 'org' in raw['host']:
                taxonomies.append(self.build_taxonomy(level, namespace, 'org', raw['host']['org']))
            if 'asn' in raw['host']:
                taxonomies.append(self.build_taxonomy(level, namespace, 'asn', raw['host']['asn']))
        elif self.service == 'search':
                taxonomies.append(self.build_taxonomy(level,namespace, 'search', 'OSINT'))
        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)

        self.shodan_client = ShodanAPIPublic(self.shodan_key)
        if self.service == 'host':
            ip = self.getParam('data', None, 'Data is missing')
            results = {'reverse_dns': {'hostnames': self.shodan_client.reverse_dns(ip)[ip]},
                       'host': self.shodan_client.host(ip)}
            self.report(results)
        if self.service == 'search':
            domain = self.getParam('data', None, 'Data is missing')
            result = {'dns_resolve': self.shodan_client.dns_resolve(domain),
                      'infos_domain': self.shodan_client.info_domains(domain)}
            self.report(result)


if __name__ == '__main__':
    ShodanAnalyzer().run()
