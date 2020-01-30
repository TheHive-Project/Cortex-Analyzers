#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from pybinaryedge import BinaryEdgeNotFound, BinaryEdge as BE


class BinaryEdge(Analyzer):
    """
    BinaryEdge- https://docs.binaryedge.io/api-v2/  | https://pybinaryedge.readthedocs.io/en/latest/index.html
    """

    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param('config.key', None, 'Missing API key')
        self.be = BE(self.api_key)

    def run(self):
        try:
            if self.data_type == 'ip':
                ip = self.get_data()
                results = self.be.host(ip)
                # Add a key if web-request data is present
                web_request = ''
                for event in results['events']:
                    if 'results' in event:
                        for result in event['results']:
                            if result['origin']['type'] == 'http' or result['origin']['type'] == 'https':
                                results['web_request'] = True

                self.report(results)
            elif self.data_type == 'other':
                page = self.get_param('parameters.page', 1, None)
                search = self.get_data()
                results = self.be.host_search(search, page)
                self.report(results)
            else:
                self.notSupported()

        except BinaryEdgeNotFound as e:
            # The API returned no results, we want some json rather than an exception so fake some
            results = {"total": 0, "targets_found": 0, "query": self.get_data()}
            self.report(results)
        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        level = 'info'
        namespace = 'BinaryEdge'

        if raw['total'] == 0:
            total = 0
        elif self.data_type == 'other':
            total = raw['total']
        else:
            total = len(raw['events'])

        taxonomies = [self.build_taxonomy(level, namespace, 'Results', str(total))]
        return {'taxonomies': taxonomies}


if __name__ == '__main__':
    BinaryEdge().run()