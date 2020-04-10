#!/usr/bin/env python2
# encoding: utf-8
import datetime
from urllib2 import HTTPError
from dnsdb_query import DnsdbClient, QueryError
from cortexutils.analyzer import Analyzer


class DnsDbAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            'config.service', None, 'Service parameter is missing')
        self.dnsdb_server = self.get_param(
            'config.server', None, 'Missing DNSDB server name')
        self.dnsdb_key = self.get_param(
            'config.key', None, 'Missing DNSDB API key')

    def execute_dnsdb_service(self, client):
        data = self.get_data()
        rrtype = self.get_param('parameters.rrtype', None, None)
        bailiwick = self.get_param('parameters.bailiwick', None, None)
        before = self.get_param('parameters.before', None, None)
        after = self.get_param('parameters.after', None, None)

        if self.service == 'domain_name' and self.data_type in ['domain', 'fqdn']:
            return client.query_rrset(data, rrtype=rrtype, bailiwick=bailiwick, before=before, after=after)
        elif self.service == 'ip_history' and self.data_type == 'ip':
            return client.query_rdata_ip(data, before=before, after=after)
        elif self.service == 'name_history' and self.data_type in ['domain', 'fqdn']:
            return client.query_rdata_name(data, rrtype=rrtype, before=before, after=after)
        else:
            self.error('Unknown DNSDB service or invalid data type')

    def update_date(self, field, row):
        if field in row:
            row[field] = datetime.datetime.utcfromtimestamp(
                row[field]).strftime('%Y%m%dT%H%M%S') + '+0000'
        return row

    def summary(self, raw):
        # taxonomy = {"level": "info", "namespace": "Farsight", "predicate": "DNSDB", "value": 0}
        taxonomies = []
        level = "info"
        namespace = "Farsight"
        predicate = "DNSDB"

        if "records" in raw:
            r = len(raw["records"])

            if r == 0 or r == 1:
                value = "{} record".format(r)
            else:
                value = "{} records".format(r)

            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {'taxonomies': taxonomies}

    def run(self):
        try:
            client = DnsdbClient(self.dnsdb_server, self.dnsdb_key)
            self.report({
                "records": map(lambda r: self.update_date('time_first', self.update_date('time_last', r)),
                               self.execute_dnsdb_service(client))
            })
        except HTTPError, e:
            if e.code != 404:
                self.unexpectedError(e)
            else:
                self.report({"records": []})


if __name__ == '__main__':
    DnsDbAnalyzer().run()
