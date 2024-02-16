#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from URLhaus_client import URLhausClient


class URLhausAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def run(self):
        data = self.get_data()
        if not data:
            self.error('No observable or file given.')

        results = {}
        if self.data_type == 'url':
            results = URLhausClient.search_url(data)
        elif self.data_type in ['domain', 'fqdn', 'ip']:
            results = URLhausClient.search_host(data)
        elif self.data_type == 'hash':
            if len(data) in [32, 64]:
                results = URLhausClient.search_payload(data)
            else:
                self.error('Only sha256 and md5 supported by URLhaus.')
        else:
            self.error('Datatype not supported.')

        results.update({
            'data_type': self.data_type
        })
        self.report(results)

    def summary(self, raw):
        taxonomies = []
        namespace = "URLhaus"

        if raw['query_status'] == 'no_results' \
        or raw['query_status'] == 'ok' and raw['md5_hash'] == None and raw['sha256_hash'] == None:
            taxonomies.append(self.build_taxonomy(
                'info',
                namespace,
                'Search',
                'No results'
            ))
        else:
            if self.data_type == 'url':
                taxonomies.append(self.build_taxonomy(
                    'malicious',
                    namespace,
                    'Threat',
                    raw['threat']
                ))
            elif self.data_type in ['domain', 'fqdn', 'ip']:
                threat_types = []
                for url in raw['urls']:
                    if url['threat'] not in threat_types:
                        threat_types.append(url['threat'])
                taxonomies.append(self.build_taxonomy(
                    'malicious',
                    namespace,
                    'Threat' if len(threat_types) == 1 else 'Threats',
                    ','.join(threat_types)
                ))
            elif self.data_type == 'hash':
                taxonomies.append(self.build_taxonomy(
                    'malicious',
                    namespace,
                    'Signature',
                    raw['signature'] if raw['signature'] and raw['signature'] != 'null' else 'Unknown'
                ))
        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    URLhausAnalyzer().run()
