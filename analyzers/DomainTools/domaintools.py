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
        self.service = self.getParam(
            'config.service', None, 'Service parameter is missing')

    def summary(self, raw):
        r = {
            "service": self.service,
            "dataType": self.data_type
        }

        taxonomy = {"level": "info", "namespace": "DT", "predicate": "Info", "value": 0}
        taxonomies = []

        if("ip_addresses" in raw):
            r["ip"] = {
                "address": raw["ip_addresses"]["ip_address"],
                "domain_count": raw["ip_addresses"]["domain_count"]
            }

        if("domain_count" in raw):
            r["domain_count"] = {
                "current": raw["domain_count"]["current"],
                "historic": raw["domain_count"]["historic"]
            }

        if("registrant" in raw):
            r["registrant"] = raw["registrant"]
        elif("response" in raw and "registrant" in raw["response"]):
            r["registrant"] = raw["response"]["registrant"]

        if("parsed_whois" in raw):
            r["registrar"] = raw["parsed_whois"]["registrar"]["name"]
            #

        if("name_server" in raw):
            r["name_server"] = raw["name_server"]["hostname"]
            r["domain_count"] = raw["name_server"]["total"]



        # Prepare predicate and value for each service
        if r["service"] == "reverse-ip":
            report["predicate"] = "Reverse_IP"
            taxonomy["value"] = "\"{}, {} domains\"".format(r["ip"]["address"], r["ip"]["domain_count"])
            taxonomies.append(taxonomy)

        if r["service"] == "name-server-domains":
            taxonomy["predicate"] = "Reverse_Name_Server"
            taxonomy["value"] = "\"{}, {} domains\"".format(r["name_server"], r["domain_count"])
            taxonomies.append(taxonomy)

        if r["service"] == "reverse-whois":
            taxonomy["predicate"] = "Reverse_Whois"
            taxonomy["value"] = "\"curr:{} / hist:{} domains\"".format(r["domain_count"]["current"], r["domain_count"]["historic"])
            taxonomies.append(taxonomy)

        if r["service"] == "whois/history":
            taxonomy["predicate"] = "Whois_History"
            taxonomy["value"] = "\"{}, {} domains \"".format(r["name_server"], r["domain_count"])
            taxonomies.append(taxonomy)

        if (r["service"] == "whois/parsed") or (r['service'] == "whois"):
            taxonomy["predicate"] = "Whois"
            taxonomy["value"] = "\"REGISTRAR:{}\"".format(r["registrar"])
            taxonomies.append(taxonomy)
            taxonomy["value"] = "\"REGISTRANT:{}\"".format(r["registrant"])
            taxonomies.append(taxonomy)

        result = {'taxonomies': taxonomies}
        return result

    def run(self):
        data = self.getData()

        if 'proxy' in self.artifact['config']:
            del self.artifact['config']['proxy']

        if self.service == 'reverse-ip' and self.data_type == 'ip':
            self.service = 'host-domains'

        if self.service == 'reverse-whois':
            query = {}
            query['terms'] = data
            query['mode'] = "purchase"
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
                configuration = Configuration(self.getParam('config'))
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
