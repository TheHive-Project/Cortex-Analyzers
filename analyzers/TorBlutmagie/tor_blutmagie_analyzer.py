#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
import tor_blutmagie


class TorBlutmagieAnalyzer(Analyzer):
    """Cortex analyzer to query TorBlutmagie for exit nodes IP addresses and/or names"""
    def __init__(self):
        Analyzer.__init__(self)
        self.cache_duration = self.get_param('config.cache.duration', 3600)
        self.cache_root = self.get_param(
            'config.cache.root', '/tmp/cortex/tor_project'
        )

        self.client = tor_blutmagie.TorBlutmagieClient(
            cache_duration=self.cache_duration,
            cache_root=self.cache_root
        )

    def summary(self, raw):
        taxonomies = []
        if ('nodes' in raw):
            r = len(raw['nodes'])
            if r == 0 or r == 1:
                value = "{} node".format(r)
            else:
                value = "{} nodes".format(r)

            if r > 0:
                level = 'suspicious'
            else:
                level = 'info'
            taxonomies.append(
                self.build_taxonomy(level, 'TorBlutmagie', 'Node', value))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type not in ['ip', 'domain', 'fqdn']:
            return self.error('Not an IP address, FQDN or domain name')
        report = self.client.search_tor_node(self.data_type, self.get_data())
        self.report(report)


if __name__ == '__main__':
    TorBlutmagieAnalyzer().run()
