#!/usr/bin/env python3
# -*- coding: utf-8 -*

from cortexutils.analyzer import Analyzer

import checkdmarc

class DomainMailSPFDMARC(Analyzer):
        def __init__(self):
                Analyzer.__init__(self)
                self.name = "DomainMailSPFDMARC"
        def summary(self, raw):
                taxonomies = []
                level = "malicious"
                level_s = "suspicious"
                level_sa = "safe"
                namespace = "DomainMailSPF_DMARC"
                predicate = "tag"

                if 'error' in raw['DomainMailSPFDMARC_info']['DomainMailSPFDMARC']['dmarc']:
                        if 'error' in raw['DomainMailSPFDMARC_info']['DomainMailSPFDMARC']['spf']:
                                taxonomies.append(self.build_taxonomy(level, namespace,"DMARC","no"))
                                taxonomies.append(self.build_taxonomy(level, namespace,"SPF","no"))
                        else:
                                taxonomies.append(self.build_taxonomy(level_sa, namespace,"SPF","yes"))
                                taxonomies.append(self.build_taxonomy(level_s, namespace,"DMARC","no"))
                else:
                        if 'error' in raw['DomainMailSPFDMARC_info']['DomainMailSPFDMARC']['spf']:
                                taxonomies.append(self.build_taxonomy(level_s, namespace,"SPF","no"))
                                taxonomies.append(self.build_taxonomy(level_sa, namespace,"DMARC","yes"))
                        else:
                                taxonomies.append(self.build_taxonomy(level_sa, namespace,"SPF","yes"))
                                taxonomies.append(self.build_taxonomy(level_sa, namespace,"DMARC","yes"))

                return {'taxonomies': taxonomies}
        def get_info(self, data):
                try:
                        result = checkdmarc.check_domains(data.split()) 
                except ValueError:
                        print("Explotioooooooo")
                return {"DomainMailSPFDMARC": dict(result)}

        def run(self):
                if self.data_type == 'domain' or self.data_type == 'fqdn':
                        data = self.get_data()
                        self.report({"DomainMailSPFDMARC_info": self.get_info(data)})

if __name__ == '__main__':
        DomainMailSPFDMARC().run()
