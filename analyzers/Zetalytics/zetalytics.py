#!/usr/bin/env python3

import requests
from zetalytics-api import Zetalytics

from cortexutils.analyzer import Analyzer



class ZetalyticsAnalyzer(Analyzer):
    """
    Zetalytics APIv1
    """

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.zetalytics_key = self.get_param('config.key', None, 'Missing Zetalytics API key')
        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.proxies = self.get_param('config.proxy', None)
        self.zl = Zetalytics(token=self.zetalytics_key)

    def call_api(self, instance, data, func_name):
        return getattr(instance, func_name)(q=data)

    def run(self):

        try:
            data = self.get_data()
            try:
                response = self.call_api(self.zl, data, self.service)
                print(response)
                json_response = response
                response_list = json_response if isinstance(json_response, list) else [json_response]
                self.report({'values': response_list})
            except Exception as e:
                self.error(e)
        except Exception as e:
            self.unexpectedError(e)

    def artifacts(self, raw):
        artifacts = []
        #TODO: Collect more information and check for and remove duplicates
        if raw and 'values' in raw:
            if self.service == "cname2qname":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['value'])))
            if self.service == "domain2aaaa":
                for result in raw['values'][0]['results']:
                    for result in raw['values']['results']:
                        artifacts.append(self.build_artifact('ip', str(result['value'])))
            if self.service == "domain2cname":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('fqdn', str(result['qname'])))
            if self.service == "domain2d8s":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('other', str(result['response']['o'])))
                    artifacts.append(self.build_artifact('domain', str(result['hname'])))
                    artifacts.append(self.build_artifact('domain', str(result['server'])))
                    artifacts.append(self.build_artifact('domain', str(result['refer'])))
                    artifacts.append(self.build_artifact('other', str(result['response']['r'])))
                    artifacts.append(self.build_artifact('mail', str(result['response'['x']['owner']])))
                    artifacts.append(self.build_artifact('mail', str(result['response']['x']['tech'])))
                    artifacts.append(self.build_artifact('mail', str(result['response']['x']['admin'])))
                    for n in raw['values'][0]['results']:
                        artifacts.append(self.build_artifact('fqdn', str(n)))
            if self.service == "domain2ip":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('ip', str(result['value'])))
            if self.service == "domain2malwaredns":
                # artifacts.append({'type': 'autonomous-system', 'value': str(raw['as'])})
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['hname'])))
                    for ip in result['iplog']:
                        artifacts.append(self.build_artifact('ip', str(ip['ip'])))
                    artifacts.append(self.build_artifact('hash', str(result['hash'])))
            if self.service == "domain2malwarehttp":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['hname'])))
                    for ip in result['iplog']:
                        artifacts.append(self.build_artifact('ip', str(ip['ip'])))
                    artifacts.append(self.build_artifact('hash', str(result['hash'])))
            if self.service == "domain2mx":
                for result in raw['values'][0]['results']:
                    artifacts.append({'type': 'domain', 'value': str(result['value'])})
            if self.service == "domain2ns":
                for result in raw['values'][0]['results']:
                    artifacts.append({'type': 'fqdn', 'value': str(result['value'])})
            if self.service == "domain2nsglue":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('fqdn', str(result['hname'])))
                    artifacts.append(self.build_artifact('ip', str(result['ip'])))
            if self.service == "domain2ptr":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['domain'])))
                    artifacts.append(self.build_artifact('fqdn', str(result['qname'])))
                    artifacts.append(self.build_artifact('other', str(result['hname'])))
            if self.service == "domain2txt":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['domain'])))
                    artifacts.append(self.build_artifact('fqdn', str(result['qname'])))
                    artifacts.append(self.build_artifact('other', str(result['value'])))
            if self.service == "domain2whois":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('other', str(result['whois'])))
                    artifacts.append(self.build_artifact('fqdn', str(result['server'])))
                    artifacts.append(self.build_artifact('fqdn', str(result['refer'])))
            if self.service == "email_address":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['d'])))
                    artifacts.append(self.build_artifact('other', str(result['r'])))
                    artifacts.append(self.build_artifact('other', str(result['o'])))
                    for n in result['n']:
                        artifacts.append(self.build_artifact('fqdn', str(n)))
                    for email in result['emails']:
                        artifacts.append(self.build_artifact('mail', str(email['addr'])))
            if self.service == "email_domain":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['d'])))
                    artifacts.append(self.build_artifact('other', str(result['r'])))
                    artifacts.append(self.build_artifact('other', str(result['o'])))
                    for n in result['n']:
                        artifacts.append(self.build_artifact('fqdn', str(n)))
                    for email in result['emails']:
                        artifacts.append(self.build_artifact('mail', str(email['addr'])))
            if self.service == "email_user":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['d'])))
                    artifacts.append(self.build_artifact('other', str(result['r'])))
                    artifacts.append(self.build_artifact('other', str(result['o'])))
                    for n in result['n']:
                        artifacts.append(self.build_artifact('fqdn', str(n)))
                    for email in result['emails']:
                        artifacts.append(self.build_artifact('mail', str(email['addr'])))
            if self.service == "hash2malwaredns":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['hname'])))
                    for ip in result['iplog']:
                        artifacts.append(self.build_artifact('ip', str(ip['ip'])))
                    artifacts.append(self.build_artifact('hash', str(result['hash'])))
            if self.service == "hash2malwarehttp":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['hname'])))
                    for ip in result['iplog']:
                        artifacts.append(self.build_artifact('ip', str(ip['ip'])))
                    artifacts.append(self.build_artifact('hash', str(result['hash'])))
            if self.service == "hostname":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['domain'])))
                    artifacts.append(self.build_artifact('fqdn', str(result['qname'])))
                    artifacts.append(self.build_artifact('fqdn', str(result['value'])))
            if self.service == "ip":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['domain'])))
                    artifacts.append(self.build_artifact('fqdn', str(result['qname'])))
                    artifacts.append(self.build_artifact('ip', str(result['value'])))
            if self.service == "ip2malwaredns":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['hname'])))
                    for ip in result['iplog']:
                        artifacts.append(self.build_artifact('ip', str(ip['ip'])))
                    artifacts.append(self.build_artifact('hash', str(result['hash'])))
            if self.service == "ip2malwarehttp":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['hname'])))
                    for ip in result['iplog']:
                        artifacts.append(self.build_artifact('ip', str(ip['ip'])))
                    artifacts.append(self.build_artifact('hash', str(result['hash'])))
            if self.service == "ip2nsglue":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('fqdn', str(result['hname'])))
                    artifacts.append(self.build_artifact('ip', str(result['ip'])))
            if self.service == "mx2domain":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['domain'])))
                    artifacts.append(self.build_artifact('fqdn', str(result['qname'])))
                    artifacts.append(self.build_artifact('domain', str(result['value'])))
            if self.service == "ns2domain":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('domain', str(result['domain'])))
                    for ns in result['ns']:
                        artifacts.append(self.build_artifact('fqdn', str(ns)))
            if self.service == "subdomains":
                for result in raw['values'][0]['results']:
                    artifacts.append(self.build_artifact('fqdn', str(result['qname'])))
        return artifacts

    def summary(self, raw):
        taxonomies = []
        #TODO: Detect the different types of results and turn them into meaninful reports
        if raw and 'values' in raw and raw['values'][0]['returning'] > 0:
            taxonomies.append(self.build_taxonomy('info','Zetalytics', 'Records', raw['values'][0]['returning']))
        else:
            taxonomies.append(self.build_taxonomy('info','Zetalytics', 'Records', 0))

        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    ZetalyticsAnalyzer().run()
