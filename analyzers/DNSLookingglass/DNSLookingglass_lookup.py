#!/usr/bin/env python3
# encoding: utf-8
import json
import requests
import iocextract
from cortexutils.analyzer import Analyzer

class DNSLookingglassAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def lookingglass_checkdomain(self, data):
        url = 'https://isc.sans.edu/api/dnslookup/%s?json' % data
        r = requests.get(url)

        return json.loads(r.text)

    def artifacts(self, raw):
        artifacts = []
        ipv4s = list(iocextract.extract_ipv4s(str(raw)))
        ipv6s = list(iocextract.extract_ipv6s(str(raw)))

        if ipv4s:
            ipv4s = list(dict.fromkeys(ipv4s))
            for i in ipv4s:
                artifacts.append(self.build_artifact('ip',str(i)))

        if ipv6s:
            ipv6s = list(dict.fromkeys(ipv6s))
            for j in ipv6s:
                artifacts.append(self.build_artifact('ip',str(j)))

        return artifacts

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Lookingglass"
        predicate = "ERR"
        value = "-"

        value = "{} hit(s)".format(raw['count'])
        predicate = raw['hits']

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def get_hits(self, hits):
        if hits == 0:
            return("NXDOMAIN")
        elif hits >= 1:
            return("DomainExist")
        else:
            return("Error")

    def run(self):
        if self.data_type in ['domain', 'fqdn']:
            data = self.get_param('data', None, 'Domain is missing')
            r = self.lookingglass_checkdomain(data)

            results = dict()
            results['results'] = list()

            if len(r) != 0:
                for hit in r:
                    result = dict()
                    try:
                        result['answer'] = hit['answer']
                        result['status'] = hit['status']
                        result['country'] = hit['country']
                        results['results'].append(result)
                    except KeyError:
                        pass

                results['hits'] = self.get_hits(int(len(results['results'])))
                results['count'] = int(len(results['results']))

                self.report(results)
            else:
                self.error('No domain found')
        else:
            self.error('Invalid data type')

if __name__ == '__main__':
    DNSLookingglassAnalyzer().run()
