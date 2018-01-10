#!/usr/bin/env python
# encoding: utf-8
import sys
import os
import json
import codecs
from domaintools.api.request import Request, Configuration

from domaintools.exceptions import NotFoundException
from domaintools.exceptions import NotAuthorizedException
from domaintools.exceptions import ServiceUnavailableException

from cortexutils.analyzer import Analyzer


class DomainToolsAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            'config.service', None, 'Service parameter is missing')

    def summary(self, raw):
        r = {
            "service": self.service,
            "dataType": self.data_type
        }

        if "ip_addresses" in raw:
            r["ip"] = {
                "address": raw["ip_addresses"]["ip_address"],
                "domain_count": raw["ip_addresses"]["domain_count"]
            }

        if "domain_count" in raw:
            r["domain_count"] = {
                "current": raw["domain_count"]["current"],
                "historic": raw["domain_count"]["historic"]
            }

        if "registrant" in raw:
            r["registrant"] = raw["registrant"]
        elif "response" in raw and "registrant" in raw["response"]:
            r["registrant"] = raw["response"]["registrant"]

        if "parsed_whois" in raw:
            r["registrar"] = raw["parsed_whois"]["registrar"]["name"]
            #

        if "name_server" in raw:
            r["name_server"] = raw["name_server"]["hostname"]
            r["domain_count"] = raw["name_server"]["total"]

        taxonomies = []

        # Prepare predicate and value for each service
        if r["service"] == "reverse-ip":
            taxonomies.append(self.build_taxonomy("info", "DT", "Reverse_IP","\"{}, {} domains\"".format(r["ip"]["address"], r["ip"]["domain_count"])))

        if r["service"] == "name-server-domains":
            taxonomies.append(self.build_taxonomy("info", "DT", "Reverse_Name_Server","\"{}, {} domains\"".format(r["name_server"], r["domain_count"])))

        if r["service"] == "reverse-whois":
            taxonomies.append(self.build_taxonomy("info", "DT", "Reverse_Whois","\"curr:{} / hist:{} domains\"".format(r["domain_count"]["current"], r["domain_count"]["historic"])))

        if r["service"] == "whois/history":
            taxonomies.append(self.build_taxonomy("info", "DT", "Whois_History","\"{}, {} domains \"".format(r["name_server"], r["domain_count"])))

        if r["service"] == "whois/parsed" or r['service'] == "whois":
            if r["registrar"]:
                taxonomies.append(self.build_taxonomy("info", "DT", "Whois", "\"REGISTRAR:{}\"".format(r["registrar"])))
            if r["registrant"]:
                taxonomies.append(self.build_taxonomy("info", "DT", "Whois", "\"REGISTRANT:{}\"".format(r["registrant"])))

        result = {'taxonomies': taxonomies}
        return result

    def run(self):
        data = self.get_data()

        if 'proxy' in self.artifact['config']:
            del self.artifact['config']['proxy']

        if self.service == 'reverse-ip' and self.data_type == 'ip':
            self.service = 'host-domains'

        if self.service == 'reverse-whois':
            query = {
                'terms': data,
                'mode': "purchase"
            }
            data = ''
        else:
            query = {}

        if (self.service == 'reverse-ip' and self.data_type == 'domain') or \
                (self.service == 'host-domains' and self.data_type == 'ip') or \
                (self.service == 'name-server-domains' and self.data_type == 'domain') or \
                (self.service == 'whois/history' and self.data_type == 'domain') or \
                (self.service == 'whois/parsed' and self.data_type == 'domain') or \
                (self.service == 'reverse-whois') or \
                (self.service == 'whois' and self.data_type == 'ip'):
            response = {}

            try:
                configuration = Configuration(self.get_param('config'))
                response = Request(configuration).service(self.service).domain(data).where(query).toJson().execute()

                r = json.loads(response)
                if 'response' in r:
                    self.report(r['response'])
                elif 'error' in r and 'message' in r['error']:
                    self.error(r['error']['message'])
                else:
                    self.report(r)

            except NotFoundException:
                self.error(self.data_type.capitalize() + " not found")
            except NotAuthorizedException:
                self.error("An authorization error occurred")
            except ServiceUnavailableException:
                self.error("DomainTools Service is currenlty unavailable")
            except Exception as e:
                self.unexpectedError(e)

        else:
            self.error('Unknown DomainTools service or invalid data type')


if __name__ == '__main__':
    DomainToolsAnalyzer().run()
