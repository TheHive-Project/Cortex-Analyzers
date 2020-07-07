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
        namespace = "DomainMailSPF_DMARC"

        if 'error' in raw['DomainMailSPFDMARC']['dmarc']:
            if 'error' in raw['DomainMailSPFDMARC']['spf']:
                taxonomies.append(self.build_taxonomy("malicious", namespace,"DMARC","no"))
                taxonomies.append(self.build_taxonomy("malicious", namespace,"SPF","no"))
            else:
                taxonomies.append(self.build_taxonomy("safe", namespace,"SPF","yes"))
                taxonomies.append(self.build_taxonomy("suspicious", namespace,"DMARC","no"))
        else:
            if 'error' in raw['DomainMailSPFDMARC']['spf']:
                taxonomies.append(self.build_taxonomy("suspicious", namespace,"SPF","no"))
                taxonomies.append(self.build_taxonomy("safe", namespace,"DMARC","yes"))
            else:
                taxonomies.append(self.build_taxonomy("safe", namespace,"SPF","yes"))
                taxonomies.append(self.build_taxonomy("safe", namespace,"DMARC","yes"))
        
        return {'taxonomies': taxonomies}
        
    def get_info(self, data):
        try:
            result = checkdmarc.check_domains(data.split()) 
        except Exception as e :
            self.error(e)
        return {"DomainMailSPFDMARC": dict(result)}

    def run(self):
        if self.data_type == 'domain' or self.data_type == 'fqdn':
            self.report(self.get_info(self.get_data()))
        else:
            self.error('Data type not supported. Please use this analyzer with data types domain or fqdn.')

if __name__ == '__main__':
    DomainMailSPFDMARC().run()
