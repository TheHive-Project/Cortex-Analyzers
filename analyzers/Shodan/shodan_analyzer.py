#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.analyzer import Analyzer
from shodan_api import ShodanAPIPublic
from shodan.exception import APIError


class ShodanAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.shodan_key = self.get_param('config.key', None, 'Missing Shodan API key')
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.shodan_client = None


    def encode(self, x):
            if isinstance(x, str):
                return x.encode('utf-8', 'ignore').decode('utf-8', 'ignore')
            elif isinstance(x, dict):
                return {k: self.encode(v) for k, v in x.items()}
            elif isinstance(x, list):
                return [self.encode(k) for k in x]
            else:
                return x

    def execute_shodan_service(self, data):
        if self.service in ['host', 'host_history']:
            results = {'host': self.shodan_client.host(data, history=True if self.service == 'host_history' else False)}
            return results
        elif self.service == 'dns_resolve':
            results = {'records': self.shodan_client.dns_resolve(data)}
            return results
        elif self.service == 'reverse_dns':
            results = {'records': self.shodan_client.reverse_dns(data)}
            return results
        elif self.service == 'search':
            page = self.get_param('parameters.page', 1, None)
            results = {'records': self.shodan_client.search(data, page)}
            return results
        elif self.service == 'info_domain':
            results = {'info_domain': self.shodan_client.info_domains(data)}
            return results
        else:
            self.error("Unknown service")

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Shodan"
        predicate = "Location"
        if self.service in ['host', 'host_history']:
            if 'country_name' in raw['host']:
                value = raw['host']['country_name']
                taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
            if 'org' in raw['host']:
                taxonomies.append(self.build_taxonomy(level, namespace, 'Org', raw['host']['org']))
            if 'asn' in raw['host']:
                taxonomies.append(self.build_taxonomy(level, namespace, 'ASN', raw['host']['asn']))
        elif self.service == 'info_domain':
            if 'ips' in raw['infos_domain']:
                value = "{}".format(len(raw['infos_domain']['ips']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'IPs', value))
            if 'all_domains' in raw['infos_domain']:
                value = "{}".format(len(raw['infos_domain']['all_domains']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'Domains', value))
            if 'asn' in raw['infos_domain']:
                value = "{}".format(len(raw['infos_domain']['asn']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'ASNs', value))
            if 'isp' in raw['infos_domain']:
                value = "{}".format(len(raw['infos_domain']['isp']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'ISPs', value))
        elif self.service == 'dns_resolve':
            value = "{}".format(len(raw['records']))
            taxonomies.append(self.build_taxonomy(level, namespace, 'DNS resolutions', value))
        elif self.service == 'reverse_dns':
            nb_domains = 0
            for k in raw['records'].keys():
                nb_domains += len(raw['records'][k])
            value = "{}".format(len(nb_domains))
            taxonomies.append(self.build_taxonomy(level, namespace, 'Reverse DNS resolutions', value))
        elif self.service == 'search':
            value = "{}".format(raw['records']['total'])
            taxonomies.append(self.build_taxonomy(level, namespace, 'Hosts', value))
        return {'taxonomies': taxonomies}

    def run(self):
        try:
            self.shodan_client = ShodanAPIPublic(self.shodan_key)
            data = self.get_param('data', None, 'Data is missing')
            results = self.execute_shodan_service(data)
            self.report(self.encode(results))
                
        except APIError as e:
            self.error(str(e))
        except Exception as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    ShodanAnalyzer().run()
