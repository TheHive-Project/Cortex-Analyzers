#!/usr/bin/env python
from cortexutils.analyzer import Analyzer
import tor_project


class TorProjectAnalyzer(Analyzer):
    """Cortex analyzer to query TorProject for exit nodes IP addresses"""
    def __init__(self):
        Analyzer.__init__(self)
        self.client = tor_project.TorProjectClient()

    def summary(self, raw):
        taxonomies = []
        level = 'info'
        value = 'false'
        if ("results" in raw):
            r = len(raw['results'])
            if r > 0:
                level = 'suspicious'
                value = 'true'
        taxonomies.append(
            self.build_taxonomy(level, 'TorProject', 'Node', value))
        return taxonomies

    def run(self):
        if self.data_type != 'ip':
            return self.error('Not an IP address')
        report = self.client.query(self.get_data())
        self.report({'results': report})


if __name__ == '__main__':
    TorProjectAnalyzer().run()
