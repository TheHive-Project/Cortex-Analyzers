#!/usr/bin/env python
# encoding: utf-8

from cortexutils.analyzer import Analyzer

from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.enrichment import EnrichmentRequest
from passivetotal.libs.ssl import SslRequest
from passivetotal.libs.whois import WhoisRequest

class PassiveTotalAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam('config.service', None, 'PassiveTotal service is missing')
        self.username = self.getParam('config.username', None, 'PassiveTotal username is missing')
        self.api_key = self.getParam('config.key', None, 'PassiveTotal API key is missing')

    def summary(self, raw):
        result = {
            'service': self.service,
            'dataType': self.data_type
        }

        # malware service
        if self.service == 'malware':
            if 'results' in raw and raw['results']:
                result['malware'] = True

        # osint service
        elif self.service == 'osint':
            if 'results' in raw and raw['results']:
                result['osint'] = True

        # passive dns service
        elif self.service == 'passive_dns':
            if 'firstSeen' in raw and raw['firstSeen']:
                result['firstSeen'] = raw['firstSeen']
            if 'lastSeen' in raw and raw['lastSeen']:
                result['lastSeen'] = raw['lastSeen']
            if 'totalRecords' in raw and raw['totalRecords']:
                result['total'] = raw['totalRecords']

        # ssl certificate details service
        elif self.service == 'ssl_certificate_details':
            if 'sha1' in raw:
                result['ssl'] = True


        # ssl certificate history service
        elif self.service == 'ssl_certificate_history':
            if 'results' in raw and raw['results']:
                result['ssl'] = True
                result['total'] = len(raw['results'])

        # unique resolutions service
        elif self.service == 'unique_resolutions':
            if 'total' in raw:
                result['total'] = raw['total']

        # whois details service
        elif self.service == 'whois_details':
            if 'registrant' in raw and 'organization' in raw['registrant'] and raw['registrant']['organization']:
                result['registrant'] = raw['registrant']['organization']
            elif 'registrant' in raw and 'name' in raw['registrant'] and raw['registrant']['name']:
                result['registrant'] = raw['registrant']['name']

            if 'registrar' in raw and raw['registrar']:
                result['registrar'] = raw['registrar']

        return result

    def run(self):
        Analyzer.run(self)

        data = self.getData()

        try:
            # enrichment service
            if self.service == 'enrichment':
                enrichment_request = EnrichmentRequest(username=self.username, api_key=self.api_key)
                result = enrichment_request.get_enrichment(query=data)
                self.report(result)

            # malware service
            elif self.service == 'malware':
                enrichment_request = EnrichmentRequest(username=self.username, api_key=self.api_key)
                result = enrichment_request.get_malware(query=data)
                self.report(result)

            # osint service
            elif self.service == 'osint':
                enrichment_request = EnrichmentRequest(username=self.username, api_key=self.api_key)
                result = enrichment_request.get_osint(query=data)
                self.report(result)

            # passive dns service
            elif self.service == 'passive_dns':
                dns_request = DnsRequest(username=self.username, api_key=self.api_key)
                result = dns_request.get_passive_dns(query=data)
                self.report(result)

            # ssl certificate details service
            elif self.service == 'ssl_certificate_details':
                ssl_request = SslRequest(username=self.username, api_key=self.api_key)
                result = ssl_request.get_ssl_certificate_details(query=data)
                self.report(result)

            # ssl certificate history service
            elif self.service == 'ssl_certificate_history':
                ssl_request = SslRequest(username=self.username, api_key=self.api_key)
                result = ssl_request.get_ssl_certificate_history(query=data)
                self.report(result)

            # unique resolutions service
            elif self.service == 'unique_resolutions':
                dns_request = DnsRequest(username=self.username, api_key=self.api_key)
                result = dns_request.get_unique_resolutions(query=data)
                self.report(result)

            # whois details service
            elif self.service == 'whois_details':
                whois_request = WhoisRequest(username=self.username, api_key=self.api_key)
                result = whois_request.get_whois_details(query=data)
                self.report(result)

            else:
                self.error('Unknown PassiveTotal service')

        except Exception as e:
            self.unexpectedError(e)

if __name__ == '__main__':
    PassiveTotalAnalyzer().run()
