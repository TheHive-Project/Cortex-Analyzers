#!/usr/bin/env python3
import pypssl
from cortexutils.analyzer import Analyzer


class CIRCLPassiveSSLAnalyzer(Analyzer):
    """This analyzer uses CIRCL.lu passiveSSL service to find either IPs connected to a given certificate or the other
    way round"""

    def __init__(self):
        Analyzer.__init__(self)
        self.user = self.get_param('config.user', None, 'PassiveSSL username is missing!')
        self.password = self.get_param('config.password', None, 'PassiveSSL password is missing!')
        self.pssl = pypssl.PyPSSL(basic_auth=(self.user, self.password))

    def query_ip(self, ip):
        """
        Queries Circl.lu Passive SSL for an ip using PyPSSL class. Returns error if nothing is found.

        :param ip: IP to query for
        :type ip: str
        :returns: python dict of results
        :rtype: dict
        """
        try:
            result = self.pssl.query(ip)
        except:
            self.error('Exception during processing with passiveSSL. '
                       'Please check the format of ip.')

        # Check for empty result
        # result is always assigned, self.error exits the function.
        if not result.get(ip, None):
            certificates = []
        else:
            certificates = list(result.get(ip).get('certificates'))
            subjects = result.get(ip).get('subjects', dict({}))

        newresult = {'ip': ip,
                     'certificates': []}
        for cert in certificates:
            if cert not in subjects:
                continue
            newresult['certificates'].append({'fingerprint': cert,
                                              'subject': subjects.get(cert).get('values')[0]})
        return newresult

    def query_certificate(self, cert_hash):
        """
        Queries Circl.lu Passive SSL for a certificate hash using PyPSSL class. Returns error if nothing is found.

        :param cert_hash: hash to query for
        :type cert_hash: str
        :return: python dict of results
        :rtype: dict
        """
        try:
            cquery = self.pssl.query_cert(cert_hash)
        except Exception:
            self.error('Exception during processing with passiveSSL. '
                       'This happens if the given hash is not sha1 or contains dashes/colons etc. '
                       'Please make sure to submit a clean formatted sha1 hash.')

        # fetch_cert raises an error if no certificate was found.
        try:
            cfetch = self.pssl.fetch_cert(cert_hash, make_datetime=False)
        except Exception:
            cfetch = {}

        return {'query': cquery,
                'cert': cfetch}

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "CIRCL"
        predicate = "PassiveSSL"

        if (self.data_type == 'hash') and ("query" in raw):
            r = raw.get('query', 0).get('hits', 0)
        if (self.data_type == 'ip') and ("certificates" in raw):
            r = len(raw['certificates'])

        if r == 0 or r == 1:
            value = "{} record".format(r)
        else:
            value = "{} records".format(r)
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}


    def artifacts(self, raw):
        artifacts = []
        if 'certificates' in raw:
            for c in raw.get('certificates'):
                tags = []
                tags += ["Certificate:{}".format(a) for a in c.get('subject').split(', ') if a.startswith('CN=')] 
                tags += ["Certificate:{}".format(a) for a in c.get('subject').split(', ') if a.startswith('O=')]
                artifacts.append(
                    self.build_artifact(
                        'hash',
                         str(c.get('fingerprint')),
                         message=str(c.get('subject')),
                         tags=tags
                )
            )
        
        if 'query' in raw:
            for ip in raw.get('query').get('seen'):
                artifacts.append(
                    self.build_artifact(
                        'ip',
                        str(ip)
                    )
                )
        return artifacts


    def run(self):
        if self.data_type == 'certificate_hash' or self.data_type == 'hash':
            data = self.get_data()
            if len(data) != 40:
                self.error('CIRCL Passive SSL expects a sha1 hash, given hash has more or less than 40 characters.')
            self.report(self.query_certificate(self.get_data()))
        elif self.data_type == 'ip':
            ip = self.get_data()
            if '/' in ip:
                self.error('CIDRs currently not supported. Please use an IP.')
            self.report(self.query_ip(ip))
        else:
            self.error('Invalid data type!')


if __name__ == '__main__':
    CIRCLPassiveSSLAnalyzer().run()
