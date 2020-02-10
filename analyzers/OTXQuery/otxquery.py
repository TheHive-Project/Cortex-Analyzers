#!/usr/bin/env python3
# encoding: utf-8
import json
import requests
import urllib
import hashlib
import io
from cortexutils.analyzer import Analyzer


class OTXQueryAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)        
        self.otx_key = self.get_param('config.key', None, 'Missing OTX API key')

    def _get_headers(self):
        return {
            'X-OTX-API-KEY': self.otx_key,
            'Accept': 'application/json'
        }

    def otx_query_ip(self, data):
        baseurl = "https://otx.alienvault.com:443/api/v1/indicators/IPv4/%s/" % data
        headers = self._get_headers()
        sections = [
            'general',
            'reputation',
            'geo',
            'malware',
            'url_list',
            'passive_dns'
        ]
        ip_ = {}
        try:
            for section in sections:
                queryurl = baseurl + section
                ip_[section] = json.loads(requests.get(queryurl, headers=headers).content)

            ip_general = ip_['general']
            ip_geo = ip_['geo']
            self.report({
                'pulse_count': ip_general.get('pulse_info', {}).get('count', "0"),
                'pulses': ip_general.get('pulse_info', {}).get('pulses', "-"),
                'whois': ip_general.get('whois', "-"),
                'continent_code': ip_geo.get('continent_code', "-"),
                'country_code': ip_geo.get('country_code', "-"),
                'country_name': ip_geo.get('country_name', "-"),
                'city': ip_geo.get('city', "-"),
                'longitude': ip_general.get('longitude', "-"),
                'latitude': ip_general.get('latitude', "-"),
                'asn': ip_geo.get('asn', "-"),
                'malware_samples': ip_.get('malware', {}).get('result', "-"),
                'url_list': ip_.get('url_list', {}).get('url_list', "-"),
                'passive_dns': ip_.get('passive_dns', {}).get('passive_dns', "-")
            })
        except Exception:
            self.error('API Error! Please verify data type is correct.')

    def otx_query_domain(self, data):
        baseurl = "https://otx.alienvault.com:443/api/v1/indicators/domain/%s/" % data
        headers = self._get_headers()
        sections = ['general', 'geo', 'malware', 'url_list', 'passive_dns']
        ip_ = {}
        try:
            for section in sections:
                queryurl = baseurl + section
                ip_[section] = json.loads(requests.get(queryurl, headers=headers).content)

            result = {
                'pulse_count': ip_.get('general', {}).get('pulse_info', {}).get('count', "0"),
                'pulses': ip_.get('general', {}).get('pulse_info', {}).get('pulses', "-"),
                'whois': ip_.get('general', {}).get('whois', "-"),
                'malware_samples': ip_.get('malware', {}).get('result', "-"),
                'url_list': ip_.get('url_list', {}).get('url_list', "-"),
                'passive_dns': ip_.get('passive_dns', {}).get('passive_dns', "-")
            }

            try:
                result.update({
                    'continent_code': ip_.get('geo', {}).get('continent_code', "-"),
                    'country_code': ip_.get('geo', {}).get('country_code', "-"),
                    'country_name': ip_.get('geo', {}).get('country_name', "-"),
                    'city': ip_.get('geo', {}).get('city', "-"),
                    'asn': ip_.get('geo', {}).get('asn', "-")
                })
            except Exception:
                pass

            self.report(result)
        except Exception:
            self.error('API Error! Please verify data type is correct.')

    def otx_query_file(self, data):
        baseurl = "https://otx.alienvault.com:443/api/v1/indicators/file/%s/" % data
        headers = self._get_headers()
        sections = ['general', 'analysis']
        ip_ = {}
        try:
            for section in sections:
                queryurl = baseurl + section
                ip_[section] = json.loads(requests.get(queryurl, headers=headers).content)

            if ip_['analysis']['analysis']:
                # file has been analyzed before
                self.report({
                    'pulse_count': ip_.get('general', {}).get('pulse_info', {}).get('count', "0"),
                    'pulses': ip_.get('general', {}).get('pulse_info', {}).get('pulses', "-"),
                    'malware': ip_.get('analysis', {}).get('malware', "-"),
                    'page_type': ip_.get('analysis', {}).get('page_type', "-"),
                    'sha1': ip_.get('analysis', {}).get('analysis', {}).get('info', {}).get('results', {}).get('sha1',
                                                                                                               "-"),
                    'sha256': ip_.get('analysis', {}).get('analysis', {}).get('info', {}).get('results', {}).get(
                        'sha256', "-"),
                    'md5': ip_.get('analysis', {}).get('analysis', {}).get('info', {}).get('results', {}).get('md5',
                                                                                                              "-"),
                    'file_class': ip_.get('analysis', {}).get('analysis', {}).get('info', {}).get('results', {}).get(
                        'file_class', "-"),
                    'file_type': ip_.get('analysis', {}).get('analysis', {}).get('info', {}).get('results', {}).get(
                        'file_type', "-"),
                    'filesize': ip_.get('analysis', {}).get('analysis', {}).get('info', {}).get('results', {}).get(
                        'filesize', "-"),
                    'ssdeep': ip_.get('analysis', {}).get('analysis', {}).get('info', {}).get('results', {}).get(
                        'ssdeep')
                })
            else:
                # file has not been analyzed before
                self.report({
                    'errortext': 'File has not previously been analyzed by OTX!',
                    'pulse_count': ip_['general']['pulse_info']['count'],
                    'pulses': ip_['general']['pulse_info']['pulses']
                })
        except Exception:
            self.error('API Error! Please verify data type is correct.')

    def otx_query_url(self, data):
        # urlencode the URL that we are searching for
        data = urllib.parse.quote_plus(data)
        baseurl = "https://otx.alienvault.com:443/api/v1/indicators/url/%s/" % data
        headers = self._get_headers()
        sections = ['general', 'url_list']
        IP_ = {}
        try:
            for section in sections:
                queryurl = baseurl + section
                IP_[section] = json.loads(requests.get(queryurl, headers=headers).content)

            self.report({
                'pulse_count': IP_.get('general', {}).get('pulse_info', {}).get('count', "0"),
                'pulses': IP_.get('general', {}).get('pulse_info', {}).get('pulses', "-"),
                'alexa': IP_.get('general', {}).get('alexa', "-"),
                'whois': IP_.get('general', {}).get('whois', "-"),
                'url_list': IP_.get('url_list', {}).get('url_list', "-")
            })
        except:
            self.error('API Error! Please verify data type is correct.')

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "OTX"
        predicate = "Pulses"
        value = "{}".format(raw["pulse_count"])
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)
        if self.data_type == 'file':
            hashes = self.get_param('attachment.hashes', None)
            if hashes is None:
                filepath = self.get_param('file', None, 'File is missing')
                sha256 = hashlib.sha256()
                with io.open(filepath, 'rb') as fh:
                    while True:
                        data = fh.read(4096)
                        if not data:
                            break
                        sha256.update(data)
                hash = sha256.hexdigest()
            else:
                # find SHA256 hash
                hash = next(h for h in hashes if len(h) == 64)
            self.otx_query_file(hash)
        elif self.data_type == 'url':
            data = self.get_param('data', None, 'Data is missing')
            self.otx_query_url(data)
        elif self.data_type == 'domain':
            data = self.get_param('data', None, 'Data is missing')
            self.otx_query_domain(data)
        elif self.data_type == 'ip':
            data = self.get_param('data', None, 'Data is missing')
            self.otx_query_ip(data)
        elif self.data_type == 'hash':
            data = self.get_param('data', None, 'Data is missing')
            self.otx_query_file(data)
        else:
            self.error('Invalid data type')


if __name__ == '__main__':
    OTXQueryAnalyzer().run()
