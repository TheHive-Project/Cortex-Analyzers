#!/usr/bin/env python3
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
        url = base_url.format(domain)

        ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36'
        req = requests.get(url, headers={'User-Agent': ua})

        if req.ok:
            try:
                content = req.content.decode('utf-8')
                data = json.loads(content.replace('}{', '},{'))
            except Exception as e:
                self.error("Error retrieving base domain information. {}".format(e))
                return None

        if wildcard:
            url2 = base_url.format("%25{}.".format(domain))
            req2 = requests.get(url2, headers={'User-Agent': ua})
            if req2.ok and not req2.headers['content-type'].startswith('text/html'):
                try:
                    content2 = req2.content.decode('utf-8')
                    data2 = json.loads(content2.replace('}{', '},{'))
                    data.extend(data2)
                except Exception as e:
                    self.error("Error retrieving wildcard information. {}".format(e))
                    return None

        for c in data:
            if c.get('min_cert_id'):
                det_url = 'https://crt.sh/?q={}&output=json'.format(c['min_cert_id'])
                try:
                    det_req = requests.get(det_url, headers={'User-Agent': ua})
                    if det_req.status_code == requests.codes.ok:
                        det_con = det_req.content.decode('utf-8')
                        sha1 = re.findall(rex, det_con)[0]
                        c['sha1'] = sha1
                    else:
                        c['sha1'] = ''
                except:
                    c['sha1'] = ''

        return data

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

    def artifacts(self, raw):
        artifacts = []
        results = raw.get('certobj', {}).get('result', [])
        for cert in results:
            if 'sha1' in cert:
                artifacts.append({'type':'certificate_hash', 'value':cert.get('sha1')})
            if 'name_value' in cert:
                artifacts.append({'type': 'fqdn', 'value': cert.get('name_value')})

        #dedup
        artifacts = [dict(t) for t in {tuple(d.items()) for d in artifacts}]
        return artifacts

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
