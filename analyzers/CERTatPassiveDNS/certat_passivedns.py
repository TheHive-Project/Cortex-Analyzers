#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from whois_wrapper import query


class CERTatPassiveDNSAnalyzer(Analyzer):
    """Very simple passive dns wrapper for pdns.cert.at. Needs no credentials because access is controlled through
    firewall rules. If you want to get access, you have to contact CERT.AT, but:
    
    CERT.AT pDNS is not a public service. It is only available for national / governmental CERTs in good standing with
    CERT.AT. For access, you have to get in contact with CERT.AT.
    """
    def __init__(self):
        Analyzer.__init__(self)
        self.limit = self.get_param('config.limit', '100')

    def run(self):
        self.report({'results': query(self.get_data(), int(self.limit))})

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "CERT.at"
        predicate = "PassiveDNS"

        results = raw.get('results')
        r = len(results)
        if r == 0 or r == 1:
            value = "{} hit".format(r)
        else:
            value = "{} hits".format(r)

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    CERTatPassiveDNSAnalyzer().run()
