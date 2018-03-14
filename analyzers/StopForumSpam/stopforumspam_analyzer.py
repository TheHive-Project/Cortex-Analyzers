#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from stopforumspam_client import StopforumspamClient


class StopforumspamAnalyzer(Analyzer):
    """docstring for StopforumspamAnalyzer."""
    def __init__(self):
        Analyzer.__init__(self)
        self.client = StopforumspamClient()

    def _format_ip_report(self, data):
        return data

    def _format_email_report(self, data):
        return data

    def summary(self, raw):
        taxonomies = []
        ns = 'SFS'
        predicate = ''
        level = ''
        value = ''
        taxonomies.append(self.build_taxonomy(level, ns, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
        if self.data_type == 'ip':
            self.report({'results': self._format_ip_report(self.client.get_data(self.data_type, self.get_data()))})
        elif self.data_type == 'mail':
            self.report({'results': self._format_email_report(self.client.get_data(self.data_type, self.get_data()))})
        else:
            self.error('Unsupported dataType {}'.format(self.data_type))


if __name__ == '__main__':
    StopforumspamAnalyzer().run()
