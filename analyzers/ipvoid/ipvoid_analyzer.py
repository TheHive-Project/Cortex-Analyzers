#!/usr/bin/env python
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import json
import requests
import re

class ipvoidAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam('config.service', 'search', 'ipvoid service is missing, default method is used')

    def summary(self, raw):
        taxonomies = []
        if raw.get('BlacklistStatus'):
            res = re.match('([^\d]*) ([^/]*)\/(\d*)', raw.get('BlacklistStatus'))
            level = "info"
            value = ""
            if res.group(1) == 'BLACKLISTED':
                level = "suspicious"
                if int(res.group(2)) > 2:
                    level = "malicious"
                value = "\""+res.group(2)+"/"+res.group(3)+"\""
            elif res.group(1) == 'POSSIBLY SAFE':
                level = "safe"
                value = "\"POSSIBLY SAFE\""
            taxonomies.append(self.build_taxonomy(level, "IPVOID", "Status", value))
            return {"taxonomies": taxonomies}

    def run(self):
        # get input data
        Analyzer.run(self)
        data = self.getParam('data', None, 'Data is missing')
        try:
            # send service
            if self.service == 'search':
                payload = {'ip': data}
                r = requests.post('http://www.ipvoid.com/ip-blacklist-check/', data=payload)
                response = r.content.decode()

                result = {}

                # ip adress information
                try:
                    result['BlacklistStatus'] = re.findall('Blacklist Status.*<span[^>]*>(.*)<\/span>',response)[0]
                    result['IPAddress'] = re.findall('IP Address.*<strong[^>]*>(.*)<\/strong>',response)[0]
                    result['ReverseDNS'] = re.findall('Reverse DNS.*<td[^>]*>(.*)<\/td>',response)[0]
                    result['ASN'] = re.findall('ASN.*<a[^>]*>(.*)<\/a>',response)[0]
                    result['ASNOwner'] = re.findall('ASN Owner.*<td[^>]*>(.*)<\/td>',response)[0]
                    result['ISP'] = re.findall('ISP.*<td[^>]*>(.*)<\/td>',response)[0]
                    result['Continent'] = re.findall('Continent.*<td[^>]*>(.*)<\/td>',response)[0]
                    result['CountryCode'] = re.findall('Country Code.*<td[^>]*>(.*)<\/td>',response)[0]
                    result['Latitude/Longitude'] = re.findall('Latitude / Longitude.*<td[^>]*>(.*)<\/td>',response)[0]
                    result['City'] = re.findall('City.*<td[^>]*>(.*)<\/td>',response)[0]
                    result['Region'] = re.findall('Region.*<td[^>]*>(.*)<\/td>',response)[0]
                except:
                    pass

                try:
                    result['report'] = re.findall('<td><i class=\"([^\"]*)\" aria-hidden=\"true\"><\/i> ([^>]*)<\/td>', response)
                except:
                    pass

                self.report(result)
            else:
                self.error('Unknown ipvoid service')

        except Exception as e:
            self.unexpectedError(e)

if __name__ == '__main__':
    ipvoidAnalyzer().run()