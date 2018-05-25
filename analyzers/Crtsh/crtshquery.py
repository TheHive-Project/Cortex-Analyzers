#!/usr/bin/env python
# encoding: utf-8

import requests
import json
from cortexutils.analyzer import Analyzer

class crtshAnalyzer(Analyzer):
    def search(self, domain, wildcard=True):
        """
        Search crt.sh for the given domain.

        domain -- Domain to search for
        wildcard -- Whether or not to prepend a wildcard to the domain
                    (default: True)

        Return a list of a certificate dict:

        {
            "issuer_ca_id": 16418,
            "issuer_name": "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3",
            "name_value": "hatch.uber.com",
            "min_cert_id": 325717795,
            "min_entry_timestamp": "2018-02-08T16:47:39.089",
            "not_before": "2018-02-08T15:47:39"
        }
	
	XML notation would also include the base64 cert: 
	https://crt.sh/atom?q={}
        """
        base_url = "https://crt.sh/?q={}&output=json"
        if wildcard:
            domain = "%25.{}".format(domain)
        url = base_url.format(domain)

        ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'
        req = requests.get(url, headers={'User-Agent': ua})

        if req.ok:
            try:
                content = req.content.decode('utf-8')
                data = json.loads("[{}]".format(content.replace('}{', '},{')))
                return data
            except Exception as err:
                self.error("Error retrieving information.")
        return None


    def __init__(self):
	Analyzer.__init__(self)

    def dumpData(self, domain):
        return {
	    'domain': domain, 
            'result': self.search(domain)
        }


    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "crt.sh"
        predicate = "Certificates"
        value = "\"\""

        if("certobj" in raw):
            value = "\"{}\"".format(len(raw["certobj"]["result"]))
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies":taxonomies}

    def run(self):
        Analyzer.run(self)

        if self.data_type == 'domain':
	    try:
                data = self.getData()
                mydata = data
                self.report({
                    'certobj': self.dumpData(mydata)
                })
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()



if __name__ == '__main__':
    crtshAnalyzer().run()
