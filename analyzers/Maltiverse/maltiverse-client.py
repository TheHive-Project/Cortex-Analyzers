#!/usr/bin/env python3
# encoding: utf-8
import sys
import time
import hashlib
import urllib

from cortexutils.analyzer import Analyzer
from maltiverse import Maltiverse

class MaltiverseAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        # self.username = self.get_param('config.username', None, 'Missing Maltiverse API Username')
        # self.password = self.get_param('config.password', None, 'Missing Maltiverse API Password')
        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.proxies = self.get_param('config.proxy', None)
        self.m = Maltiverse()

    def maltiverse_query_ip(self, data):
        try:
            result = self.m.ip_get(data)
            self.report({
                'registrant_name': result.get("registrant_name","-"),
                'last_updated': result.get("last_updated","-"),
                'asn_registry': result.get("asn_registry","-"),
                'classification': result.get("classification","-"),
                'asn_country_code': result.get("asn_country_code","-"),
                'creation_time': result.get("creation_time","-"),
                'visits': result.get("visits","-"),
                'blacklist': result.get("blacklist","-"),
                'asn_date': result.get("asn_date","-"),
                'modification_time': result.get("modification_time","-"),
                'asn_cidr': result.get("asn_cidr","-"),
                'location': result.get("location","-"),
                'country_code': result.get("country_code","-"),
                'address': result.get("address","-"),
                'ip_addr': result.get("ip_addr","-"),
                'cidr': result.get("cidr","-"),
                'tag': result.get("tag","-"),
                'type': result.get("type","-"),
                'email': result.get("email","-")
            })
        except Exception:
            self.error('API Error! Please verify data type is correct.')

    def maltiverse_query_domain(self, data):
        try:
            result = self.m.hostname_get(data)
            self.report({
                'domain': result.get("domain","-"),
                'classification': result.get("classification","-"),
                'hostname': result.get("hostname","-"),
                'creation_time': result.get("creation_time","-"),
                'domain_lenght': result.get("domain_lenght","-"),
                'resolved_ip': result.get("resolved_ip","-"),
                'modification_time': result.get("modification_time","-"),
                'domain_consonants': result.get("domain_consonants","-"),
                'visits': result.get("visits","-"),
                'tld': result.get("tld","-"),
                'entropy': result.get("entropy","-"),
                'type': result.get("type","-"),
                'as_name': result.get("as_name","-")
            })
        except Exception:
            self.error('API Error! Please verify data type is correct.')

    def maltiverse_query_file(self, data):
        try:
            result = self.m.sample_get(data)
            self.report(result)
        except Exception:
            self.error('API Error! Please verify data type is correct.')

    def maltiverse_query_url(self, data):
        # urlencode the URL that we are searching for
        #data = urllib.quote_plus(data)
        try:
            result = self.m.url_get(data)
            self.report({
                'original': data,
                'hash': hash,
                'url': result.get("url","-"),
                'type': result.get("type","-"),
                'classification': result.get("classification","-"),
                'tag': result.get("tag","-"),
                'blacklist': result.get("blacklist","-"),
                'creation_time': result.get("creation_time","-"),
                'modification_time': result.get("modification_time","-")
            })
        except:
            self.error('API Error! Please verify data type is correct.')

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Maltiverse"
        predicate = "Report"
        value = "{}".format("n/a")
        if "classification" in raw:
            if raw["classification"] == "malicious":
                level = "malicious"
            elif raw["classification"] == "suspicious":
                level = "suspicious"
            else:
                level = "safe"
            value = "{}".format(raw["classification"])

        
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
            self.maltiverse_query_file(hash)
        elif self.data_type == 'url':
            data = self.get_param('data', None, 'Data is missing')
            self.maltiverse_query_url(data)
        elif self.data_type == 'domain':
            data = self.get_param('data', None, 'Data is missing')
            self.maltiverse_query_domain(data)
        elif self.data_type == 'ip':
            data = self.get_param('data', None, 'Data is missing')
            self.maltiverse_query_ip(data)
        elif self.data_type == 'hash':
            data = self.get_param('data', None, 'Data is missing')
            self.maltiverse_query_file(data)
        else:
            self.error('Invalid data type')

if __name__ == '__main__':
    MaltiverseAnalyzer().run()
