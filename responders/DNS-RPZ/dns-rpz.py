#!/usr/bin/env python3
# encoding: utf-8

import dns
from cortexutils.responder import Responder
from dns import query
from dns import resolver
from dns import tsigkeyring
from dns import update

class DNSRPZ(Responder):
    """ DNSRPZ takes a Hive obervable of type "domain" as input
        and blocks it in your BIND RPZ using a DDNS update.
        It creates an A record with an IP address of your choosing,
        perhaps an internal remediation server.
    """
    def __init__(self):
        Responder.__init__(self)
        self.bind_server = self.get_param('config.bind_server', '127.0.0.1')
        self.tsig_keyname = self.get_param('config.tsig_keyname', 'cortex.')
        self.tsig_keyval = self.get_param('config.tsig_keyval', None, 'Missing TSIG key')
        self.tsig_hashalg = self.get_param('config.tsig_hashalg', 'HMAC-SHA512')
        self.remediation_ip = self.get_param('config.remediation_ip', '127.0.0.1')
        self.rpz_zonename = self.get_param('config.rpz_zonename', 'rpz.')

    def checkname(self, fqdn):
        """ Resolve a name.
            Return 0 if the name does NOT resolve, 1 on success.
        """
        try:
            answer = dns.resolver.query(fqdn, 'a')
        except:
            return(0)
        else:
            return(1)

    def run(self):
        Responder.run(self)

        if self.get_param('data.dataType') == 'domain':
            domain = self.get_param('data.data', None, 'No domain artifact found')
        else:
            self.error('Can only operate on "domain" observables')

        if self.checkname(domain + '.' + self.rpz_zonename) == 0:
            # Only add if the record isn't already there.
            keyring = dns.tsigkeyring.from_text({
                self.tsig_keyname : self.tsig_keyval
            })
            update = dns.update.Update(
                self.rpz_zonename,
                keyring = keyring,
                keyalgorithm = self.tsig_hashalg
            )
            update.add(domain, 30, 'a', self.remediation_ip)
            response = dns.query.tcp(update, self.bind_server)
            if response.rcode() != 0:
                self.error('Failed to add RPZ record')

        self.report({'message': 'DNS-RPZ block injected'})

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='DNS-RPZ:blocked')]


if __name__ == '__main__':
    DNSRPZ().run()
