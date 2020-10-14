#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
import vulners


class VulnersAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.api_key = self.get_param('config.key', None, 'Missing vulners api key')
        self.vulners = vulners.Vulners(api_key=self.api_key)

    def summary(self, raw):
        taxonomies = []
        namespace = "Vulners"
        if raw['service'] == 'ioc':
            predicate = "IOC"
            tags = ', '.join(raw['tags'])
            if raw['fp_descr'] and not raw['tags']:
                level = 'informative'
                value = f"{raw['ioc_score']} score"
            elif raw['fp_descr'] and raw['tags']:
                level = 'suspicious'
                value = f"{raw['ioc_score']} score / tags: {tags} / possible FP descr: {raw['fp_descr']}"
            else:
                level = 'malicious'
                value = f"{raw['ioc_score']} score / tags: {tags} "

        if raw['service'] == 'vulnerability':
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
                document_id = self.vulners.search(f"iocType:{self.data_type} AND {self.data_type}:{data}")
                if document_id or document_id['type'] == 'rst':
                    full_document_info = self.vulners.document(document_id[0]['id'],  fields=["*"])
                    ioc_report = {
                        'service': self.service,
                        'first_seen': full_document_info['published'],
                        'last_seen': full_document_info['lastseen'],
                        'tags': full_document_info['tags'],
                        'ioc_score': full_document_info['iocScore']['ioc_total'],
                        'ioc_url': full_document_info['id'],
                        'fp_descr': full_document_info['fp']['descr']
                    }
                    if self.data_type == 'ip':
                        ioc_report['geo_info'] = full_document_info['geodata']
                        ioc_report['asn_info'] = full_document_info['asn']

                    self.report(ioc_report)
                else:
                    self.error('No data found')
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
                    self.error('No data for specified CVE was found')

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
