#!/usr/bin/env python
# encoding: utf-8
import sys
import os
import json
import codecs
import time
import requests
import urllib
import hashlib
from cortexutils.analyzer import Analyzer


class OTXQueryAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam(
            'config.service', None, 'Service parameter is missing')
        self.otx_key = self.getParam('config.key', None, 'Missing OTX API key')

    def _getHeaders(self):
        return {
            'X-OTX-API-KEY': self.otx_key,
            'Accept': 'application/json'
        }

    def OTX_Query_IP(self, data):
        baseurl = "https://otx.alienvault.com:443/api/v1/indicators/IPv4/%s/" % data
        headers = self._getHeaders()
        sections = [
            'general',
            'reputation',
            'geo',
            'malware',
            'url_list',
            'passive_dns'
        ]
        IP_ = {}
        try:
            for section in sections:
                queryurl = baseurl + section
                IP_[section] = json.loads(requests.get(queryurl, headers=headers).content)

            ipGeneral = IP_['general']
            ipGeo = IP_['geo']
            self.report({
                'pulse_count': ipGeneral['pulse_info']['count'],
                'pulses': ipGeneral['pulse_info']['pulses'],
                'whois': ipGeneral['whois'],
                'continent_code': ipGeo['continent_code'],
                'country_code': ipGeo['country_code'],
                'country_name': ipGeo['country_name'],
                'city': ipGeo['city'],
                'longitude': ipGeneral['longitude'],
                'latitude': ipGeneral['latitude'],
                'asn': ipGeo['asn'],
                'malware_samples': IP_['malware']['result'],
                'url_list': IP_['url_list']['url_list'],
                'passive_dns': IP_['passive_dns']['passive_dns']
            })
        except:
            self.error('API Error! Please verify data type is correct.')

    def OTX_Query_Domain(self, data):
        baseurl = "https://otx.alienvault.com:443/api/v1/indicators/domain/%s/" % data
        headers = self._getHeaders()
        sections = ['general', 'geo', 'malware', 'url_list', 'passive_dns']
        IP_ = {}
        try:
            for section in sections:
                queryurl = baseurl + section
                IP_[section] = json.loads(requests.get(queryurl, headers=headers).content)

            result = {
                'pulse_count': IP_['general']['pulse_info']['count'],
                'pulses': IP_['general']['pulse_info']['pulses'],
                'whois': IP_['general']['whois'],
                'malware_samples': IP_['malware']['result'],
                'url_list': IP_['url_list']['url_list'],
                'passive_dns': IP_['passive_dns']['passive_dns']}

            try:
                result.update({
                    'continent_code': IP_['geo']['continent_code'],
                    'country_code': IP_['geo']['country_code'],
                    'country_name': IP_['geo']['country_name'],
                    'city': IP_['geo']['city'],
                    'asn': IP_['geo']['asn']})
            except Exception:
                pass

            self.report(result)
        except:
            self.error('API Error! Please verify data type is correct.')

    def OTX_Query_File(self, data):
        baseurl = "https://otx.alienvault.com:443/api/v1/indicators/file/%s/" % data
        headers = self._getHeaders()
        sections = ['general', 'analysis']
        IP_ = {}
        try:
            for section in sections:
                queryurl = baseurl + section
                IP_[section] = json.loads(requests.get(queryurl, headers=headers).content)

            if IP_['analysis']['analysis']:
                # file has been analyzed before
                self.report({
                    'pulse_count': IP_['general']['pulse_info']['count'],
                    'pulses': IP_['general']['pulse_info']['pulses'],
                    'malware': IP_['analysis']['malware'],
                    'page_type': IP_['analysis']['page_type'],
                    'sha1': IP_['analysis']['analysis']['info']['results']['sha1'],
                    'sha256': IP_['analysis']['analysis']['info']['results']['sha256'],
                    'md5': IP_['analysis']['analysis']['info']['results']['md5'],
                    'file_class': IP_['analysis']['analysis']['info']['results']['file_class'],
                    'file_type': IP_['analysis']['analysis']['info']['results']['file_type'],
                    'filesize': IP_['analysis']['analysis']['info']['results']['filesize'],
                    'ssdeep': IP_['analysis']['analysis']['info']['results']['ssdeep']
                })
            else:
                # file has not been analyzed before
                self.report({
                    'errortext': 'File has not previously been analyzed by OTX!',
                    'pulse_count': IP_['general']['pulse_info']['count'],
                    'pulses': IP_['general']['pulse_info']['pulses']
                })
        except:
            self.error('API Error! Please verify data type is correct.')

    def OTX_Query_URL(self, data):
        # urlencode the URL that we are searching for
        data = urllib.quote_plus(data)
        baseurl = "https://otx.alienvault.com:443/api/v1/indicators/url/%s/" % data
        headers = self._getHeaders()
        sections = ['general', 'url_list']
        IP_ = {}
        try:
            for section in sections:
                queryurl = baseurl + section
                IP_[section] = json.loads(requests.get(queryurl, headers=headers).content)

            self.report({
                'pulse_count': IP_['general']['pulse_info']['count'],
                'pulses': IP_['general']['pulse_info']['pulses'],
                'alexa': IP_['general']['alexa'],
                'whois': IP_['general']['whois'],
                'url_list': IP_['url_list']['url_list']
            })
        except:
            self.error('API Error! Please verify data type is correct.')

    def summary(self, raw):
        return {
            "pulse_count": raw["pulse_count"]
        }

    def run(self):
        Analyzer.run(self)

        if self.service == 'query':
            if self.data_type == 'file':
                hashes = self.getParam('attachment.hashes', None)
                if hashes is None:
                    filepath = self.getParam('file', None, 'File is missing')
                    hash = hashlib.sha256(open(filepath, 'r').read()).hexdigest();
                else:
                    # find SHA256 hash
                    hash = next(h for h in hashes if len(h) == 64)
                self.OTX_Query_File(hash)
            elif self.data_type == 'url':
                data = self.getParam('data', None, 'Data is missing')
                self.OTX_Query_URL(data)
            elif self.data_type == 'domain':
                data = self.getParam('data', None, 'Data is missing')
                self.OTX_Query_Domain(data)
            elif self.data_type == 'ip':
                data = self.getParam('data', None, 'Data is missing')
                self.OTX_Query_IP(data)
            elif self.data_type == 'hash':
                data = self.getParam('data', None, 'Data is missing')

                self.OTX_Query_File(data)
            else:
                self.error('Invalid data type')
        else:
            self.error('Invalid service')


if __name__ == '__main__':
    OTXQueryAnalyzer().run()
