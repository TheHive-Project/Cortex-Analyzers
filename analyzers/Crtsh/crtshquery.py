#!/usr/bin/env python
# encoding: utf-8

import requests
import json
import re
from cortexutils.analyzer import Analyzer


class CrtshAnalyzer(Analyzer):
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
        rex = '\<TH\sclass="outer">SHA-1\(Certificate\)\</TH\>\s+\<TD\sclass="outer"\>([^\<]+)\</TD\>'
        base_url = "https://crt.sh/?q={}&output=json"
        if wildcard:
            domain = "%25.{}".format(domain)
        url = base_url.format(domain)

        ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'
        req = requests.get(url, headers={'User-Agent': ua})

        if req.ok:
            try:
                content = req.content.decode('utf-8')
                data = json.loads(content.replace('}{', '},{'))
		for c in data:
                    det_url = 'https://crt.sh/?q={}&output=json'.format(c['min_cert_id'])
                    det_req = requests.get(det_url, headers={'User-Agent': ua})
                    if det_req.status_code == requests.codes.ok:
                        det_con = det_req.content.decode('utf-8')
                        sha1 = re.findall(rex, det_con)[0]
                        c['sha1'] = sha1
                    else:
                        c['sha1'] = ''
                return data
            except Exception as e:
                self.error("Error retrieving information. {}".format(e))
        return None

    def __init__(self):
        Analyzer.__init__(self)

    def dump_data(self, domain):
        return {
            'domain': domain,
            'result': self.search(domain)
        }

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "crt.sh"
        predicate = "Certificates"
        value = ""

        if "certobj" in raw:
            value = "{}".format(len(raw["certobj"]["result"]))
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        if self.data_type == 'domain':
            try:
                data = self.getData()
                mydata = data
                self.report({
                    'certobj': self.dump_data(mydata)
                })
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    CrtshAnalyzer().run()
