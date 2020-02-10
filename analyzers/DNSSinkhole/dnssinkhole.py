#!/usr/bin/env python3
import dns.resolver
from cortexutils.analyzer import Analyzer


class DNSSinkholeAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        if self.data_type != 'domain':
            self.error('DNSSinkhole Analyzer only usable with domain data type.')
 
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [self.get_param('config.ip', None, 'Bind IP server needed for querying Sinkhole.')]
        self.data = self.get_data()

    def query(self):
        try:
            out = self.resolver.query(self.data)
            dns_records = [ip.address for ip in out]
        except dns.exception.DNSException as e :
            dns_records = []
        if self.get_param('config.sink_ip', '127.0.0.2') in dns_records:
            return True
        return False

    def run(self):
        self.report({
            "is_sinkhole": self.query()
        })

    def summary(self, raw):
        taxonomies = []

        if raw.get('is_sinkhole'):
            taxonomies.append(self.build_taxonomy('malicious', 'DNSSinkhole', 'IsSinkhole', 'True'))
        else:
            taxonomies.append(self.build_taxonomy('info', 'DNSSinkhole', 'IsSinkhole', 'False'))
        return {
            "taxonomies": taxonomies
        }


if __name__ == '__main__':
    DNSSinkholeAnalyzer().run()
