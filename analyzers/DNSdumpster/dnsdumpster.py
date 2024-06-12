#!/usr/bin/env python3
# encoding: utf-8
from __future__ import print_function
import requests
import re
import iocextract

from bs4 import BeautifulSoup
from cortexutils.analyzer import Analyzer


class DNSdumpsterAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.session = requests.Session()
        self.baseurl = 'https://dnsdumpster.com'

    def run(self):
        Analyzer.run(self)
        if self.data_type == 'domain':
            try:
                domain = self.get_param('data', None, 'Observable is missing')
                result = self.dnsdumpster_query(domain)
                self.report({'result': result})
            except Exception as e:
                self.error("Error: {}".format(e))
        else:
            self.error('Invalid data type')

    def dnsdumpster_query(self, domain):
        try:
            r = self.session.get(self.baseurl)
        except requests.ConnectionError as connerr:
            self.error("Connection error. Error {}".format(connerr))

        soup = BeautifulSoup(r.content, 'html.parser')
        csrf_middleware = soup.findAll('input', attrs={'name': 'csrfmiddlewaretoken'})[0]['value']
        cookies = {'csrftoken': csrf_middleware}
        headers = {'Referer': self.baseurl,
                   'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                                 'Chrome/95.0.4638.69 Safari/537.36'}
        data = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': domain, 'user': 'free'}
        r = self.session.post(self.baseurl, cookies=cookies, data=data, headers=headers)

        if r.status_code != 200:
            self.error("Unexpected status code from. Status code: {}".format(r.status_code))
            return []

        if 'There was an error getting results' in r.content.decode('utf-8'):
            self.error("There was an error getting results")
            return []

        soup = BeautifulSoup(r.content, 'html.parser')
        tables = soup.findAll('table')
        res = {'domain': domain, 'dns_records': {}}

        res['dns_records']['dns'] = self.retrieve_results(tables[0])
        res['dns_records']['mx'] = self.retrieve_results(tables[1])
        res['dns_records']['txt'] = self.retrieve_txt_record(tables[2])
        res['dns_records']['host'] = self.retrieve_results(tables[3])
        res['dns_records']['map_url'] = '{}/static/map/{}.png'.format(self.baseurl, domain)

        return res

    def retrieve_txt_record(self, table):
        res = []
        for td in table.findAll('td'):
            res.append(td.text)
        return res

    def retrieve_results(self, table):
        res = []
        trs = table.findAll('tr')
        for tr in trs:
            tds = tr.findAll('td')
            pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
            try:
                ip = re.findall(pattern_ip, tds[1].text)[0]
                domain = str(tds[0]).split('<br/>')[0].split('>')[1].split('<')[0]
                header = ' '.join(tds[0].text.replace('\n', '').split(' ')[1:])
                reverse_dns = tds[1].find('span', attrs={}).text

                additional_info = tds[2].text
                country = tds[2].find('span', attrs={}).text
                autonomous_system = additional_info.split(' ')[0]
                provider = ' '.join(additional_info.split(' ')[1:])
                provider = provider.replace(country, '')
                data = {'domain': domain,
                        'ip': ip,
                        'reverse_dns': reverse_dns,
                        'as': autonomous_system,
                        'provider': provider,
                        'country': country,
                        'header': header}
                res.append(data)
            except Exception as err:
                self.error("Unexpected error when parsing data from DNSdumpster.com. Error {}".format(err))
        return res

    def artifacts(self, raw):
        artifacts = []
        ipv4s = list(iocextract.extract_ipv4s(str(raw)))
        ipv6s = list(iocextract.extract_ipv6s(str(raw)))
        domains = list(iocextract.extract_urls(str(raw)))

        if ipv4s:
            ipv4s = list(dict.fromkeys(ipv4s))
            for i in ipv4s:
                artifacts.append(self.build_artifact('ip', str(i)))

        if ipv6s:
            ipv6s = list(dict.fromkeys(ipv6s))
            for j in ipv6s:
                artifacts.append(self.build_artifact('ip', str(j)))

        if domains:
            domains = list(dict.fromkeys(domains))
            for k in domains:
                artifacts.append(self.build_artifact('url', str(k)))

        return artifacts

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "DNSdumpster"
        predicate = "Report"
        value = "{}".format("OK")

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    DNSdumpsterAnalyzer().run()
