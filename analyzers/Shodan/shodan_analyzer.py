#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.analyzer import Analyzer
from shodan_api import ShodanAPIPublic
from shodan.exception import APIError


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
                taxonomies.append(self.build_taxonomy(level, namespace, 'Org', raw['host']['org']))
            if 'asn' in raw['host']:
                taxonomies.append(self.build_taxonomy(level, namespace, 'ASN', raw['host']['asn']))
        elif self.service == 'search':
            if 'ips' in raw['infos_domain']:
                value = "\"{}\"".format(len(raw['infos_domain']['ips']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'IPs', value))
            if 'all_domains' in raw['infos_domain']:
                value = "\"{}\"".format(len(raw['infos_domain']['all_domains']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'Domains', value))
            if 'asn' in raw['infos_domain']:
                value = "\"{}\"".format(len(raw['infos_domain']['asn']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'ASNs', value))
            if 'isp' in raw['infos_domain']:
                value = "\"{}\"".format(len(raw['infos_domain']['isp']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'ISPs', value))

        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)

        try:
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
        except APIError as e:
            self.error(str(e))
        except Exception as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    ShodanAnalyzer().run()
