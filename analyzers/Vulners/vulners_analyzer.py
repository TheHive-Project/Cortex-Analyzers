#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
import vulners


class VulnersAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.api_key = self.get_param('config.key', None, 'Missing vulners api key')
        proxies = {
            "https": self.get_param("config.proxy_https"),
            "http": self.get_param("config.proxy_http"),
        }
        self.vulners = vulners.Vulners(api_key=self.api_key, proxies=proxies)

    def summary(self, raw):
        taxonomies = []
        namespace = "Vulners"
        if self.service == 'ioc':
            predicate = "IOC"
            if raw['results']:
                tags = ', '.join(
                    set([', '.join(result['tags']) for result in raw['results']])
                )
                level = 'malicious'
                value = f"Finded IOCs: {len(raw['results'])} / tags: {tags}"
            else:
                level = 'info'
                value = 'No results'

        if self.service == 'vulnerability':
            predicate = "CVE"
            if not raw['exploits']:
                level = 'suspicious'
                value = f"CVSS score: {raw['cvss']['score']} / Vulners score: {raw['vulners_AI']} / No exploits"
            else:
                level = 'malicious'
                value = f"CVSS score: {raw['cvss']['score']} / Vulners score: {raw['vulners_AI']} / Exploits {len(raw['exploits'])}"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.service == 'ioc':
            if self.data_type in ['ip', 'domain', 'url']:
                data = self.get_param('data', None, 'Data is missing')
                all_short_results = self.vulners.search(
                    f'type:rst AND iocType:{self.data_type} AND {self.data_type}:"{data}"')

                results = []

                if all_short_results:
                    if all_short_results[0]['type'] == 'rst' or 'type' in all_short_results[0]:

                        full_documents_info = self.vulners.documentList(
                            [doc_id['id'] for doc_id in all_short_results],  fields=["*"])

                        for document_results in full_documents_info:
                            info_from_document = full_documents_info[f'{document_results}']

                            ioc_report = {
                                'service': self.service,
                                'first_seen': info_from_document['published'],
                                'last_seen': info_from_document['lastseen'],
                                'tags': info_from_document['tags'],
                                'ioc_score': info_from_document['iocScore']['ioc_total'],
                                'ioc_url': info_from_document['id'],
                                'fp_descr': info_from_document['fp']['descr']
                            }
                            if self.data_type == 'ip':
                                ioc_report['ioc_result'] = info_from_document['ip']
                                ioc_report['geo_info'] = info_from_document['geodata']
                                ioc_report['asn_info'] = info_from_document['asn']
                            elif self.data_type == 'url':
                                ioc_report['ioc_result'] = info_from_document['url']
                            elif self.data_type == 'domain':
                                ioc_report['ioc_result'] = info_from_document['domain']

                            if 'threat' in info_from_document:
                                ioc_report['threat_family'] = info_from_document['threat']

                            results.append(ioc_report)

                        self.report({'results': results})
                else:
                    self.report({'results': 'No data found'})
            else:
                self.error('Invalid data type')

        if self.service == 'vulnerability':
            if self.data_type == 'cve':
                data = self.get_param('data', None, 'Data is missing')
                cve_info = self.vulners.document(data, fields=["*"])
                cve_exploits = self.vulners.searchExploit(data)
                full_cve_info = {}

                if cve_info:
                    full_cve_info = {
                        'service': self.service,
                        'title': cve_info['title'],
                        'published': cve_info['published'],
                        'modified': cve_info['modified'],
                        'cvss3': cve_info['cvss3'],
                        'cvss2': cve_info['cvss2'],
                        'cvss': cve_info['cvss'],
                        'vulners_AI': cve_info['enchantments']['vulnersScore'],
                        'cwe': cve_info['cwe'],
                        'description': cve_info['description'],
                        'affectedSoftware': cve_info['affectedSoftware']
                    }
                else:
                    self.report({'result': 'No data for specified CVE was found'})

                if cve_exploits:
                    full_exploit_info = []
                    for exploit in cve_exploits:
                        full_exploit_info.append({
                            'title': exploit['title'],
                            'published': exploit['published'],
                            'url': exploit['vhref']
                        })

                    full_cve_info['exploits'] = full_exploit_info
                else:
                    full_cve_info['exploits'] = False

                self.report(full_cve_info)
            else:
                self.error('Invalid data type')


if __name__ == '__main__':
    VulnersAnalyzer().run()
