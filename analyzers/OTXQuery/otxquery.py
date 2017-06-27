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
                'pulse_count': ipGeneral.get('pulse_info',{}).get('count',"0"),
                'pulses': ipGeneral.get('pulse_info',{}).get('pulses',"-"),
                'whois': ipGeneral.get('whois',"-"),
                'continent_code': ipGeo.get('continent_code', "-"),
                'country_code': ipGeo.get('country_code', "-"),
                'country_name': ipGeo.get('country_name', "-"),
                'city': ipGeo.get('city', "-"),
                'longitude': ipGeneral.get('longitude', "-"),
                'latitude': ipGeneral.get('latitude', "-"),
                'asn': ipGeo.get('asn', "-"),
                'malware_samples': IP_.get('malware',{}).get('result',"-"),
                'url_list': IP_.get('url_list',{}).get('url_list',"-"),
                'passive_dns': IP_.get('passive_dns',{}).get('passive_dns',"-")
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
                'pulse_count': IP_.get('general',{}).get('pulse_info',{}).get('count',"0"),
                'pulses': IP_.get('general',{}).get('pulse_info',{}).get('pulses',"-"),
                'whois': IP_.get('general',{}).get('whois',"-"),
                'malware_samples': IP_.get('malware',{}).get('result',"-"),
                'url_list': IP_.get('url_list',{}).get('url_list',"-"),
                'passive_dns': IP_.get('passive_dns',{}).get('passive_dns',"-")
                }

            try:
                result.update({
                    'continent_code': IP_.get('geo',{}).get('continent_code',"-"),
                    'country_code': IP_.get('geo',{}).get('country_code',"-"),
                    'country_name': IP_.get('geo',{}).get('country_name',"-"),
                    'city': IP_.get('geo',{}).get('city',"-"),
                    'asn': IP_.get('geo',{}).get('asn',"-")
                    })
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
                    'pulse_count': IP_.get('general',{}).get('pulse_info',{}).get('count',"0"),
                    'pulses': IP_.get('general',{}).get('pulse_info',{}).get('pulses',"-"),
                    'malware': IP_.get('analysis',{}).get('malware',"-"),
                    'page_type': IP_.get('analysis',{}).get('page_type',"-"),
                    'sha1': IP_.get('analysis',{}).get('analysis',{}).get('info',{}).get('results',{}).get('sha1',"-"),
                    'sha256': IP_.get('analysis',{}).get('analysis',{}).get('info',{}).get('results',{}).get('sha256',"-"),
                    'md5': IP_.get('analysis',{}).get('analysis',{}).get('info',{}).get('results',{}).get('md5',"-"),
                    'file_class': IP_.get('analysis',{}).get('analysis',{}).get('info',{}).get('results',{}).get('file_class',"-"),
                    'file_type': IP_.get('analysis',{}).get('analysis',{}).get('info',{}).get('results',{}).get('file_type',"-"),
                    'filesize': IP_.get('analysis',{}).get('analysis',{}).get('info',{}).get('results',{}).get('filesize',"-"),
                    'ssdeep': IP_.get('analysis',{}).get('analysis',{}).get('info',{}).get('results',{}).get('ssdeep')
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
                'pulse_count': IP_.get('general',{}).get('pulse_info',{}).get('count',"0"),
                'pulses': IP_.get('general',{}).get('pulse_info',{}).get('pulses',"-"),
                'alexa': IP_.get('general',{}).get('alexa',"-"),
                'whois': IP_.get('general',{}).get('whois',"-"),
                'url_list': IP_.get('url_list',{}).get('url_list',"-")
            })
        except:
            self.error('API Error! Please verify data type is correct.')

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "OTX"
        predicate = "Pulses"
        value = "\"{}\"".format(raw["pulse_count"])
        taxonomies.append(self.buid_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

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
