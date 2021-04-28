from shodan import Shodan
from urllib.parse import urljoin

import requests


class ShodanAPIPublic(Shodan):
    def __init__(self, api_key):
        Shodan.__init__(self, api_key)

    def host(self, ips, history=False, minify=False):

        host = Shodan.host(self, ips, history=history, minify=minify)
        if host:
            return host

    def info_domains(self, domain):
        results = Shodan.search(self, 'hostname:%s' % domain)

        if 'matches' in results:
            all_domains = list(set([item for r in results['matches'] for item in r['hostnames']]))
            ips = list(set([r['ip_str'] for r in results['matches']]))
            ports = list(set([r['port'] for r in results['matches']]))
            transports = list(set([r['transport'] for r in results['matches']]))
            isp = list(set([r['isp'] for r in results['matches'] if 'isp' in r]))
            asn = list(set([r['asn'] for r in results['matches'] if 'asn' in r]))
            orgs = list(set([r['org'] for r in results['matches'] if 'org' in r]))

            return {'all_domains': all_domains, 'ips': ips, 'ports': ports, 'transports': transports,
                    'isp': isp, 'asn': asn, 'orgs': orgs
                    }

    def search(self, query, page=1):
        results = Shodan.search(self, query, page=page)
        return results

    def dns_resolve(self, domain):
        payload = {'hostnames': [domain], 'key': self.api_key}
        r = requests.get(urljoin(self.base_url, 'dns/resolve'), params=payload)
        if r.status_code == requests.codes.ok:
            return r.json()

    def reverse_dns(self, ip):
        payload = {'ips': [ip], 'key': self.api_key}
        r = requests.get(urljoin(self.base_url, 'dns/reverse'), params=payload)
        if r.status_code == requests.codes.ok:
            result = r.json()
            if not result[ip]:
                result[ip] = []
            return result
