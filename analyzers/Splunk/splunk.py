#!/usr/bin/env python3
# encoding: utf-8

import splunklib.client as client
from time import sleep
from cortexutils.analyzer import Analyzer
import splunklib.results as results
import urllib
import re


class Splunk(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam('config.service', None, 'Service parameter is missing')
        self.HOST = self.getParam('config.host', None, 'Host parameter is missing')
        self.PORT = self.getParam('config.port', None, 'Port parameter is missing')
        self.USERNAME = self.getParam('config.username', None, 'Username parameter is missing')
        self.PASSWORD = self.getParam('config.password', None, 'Password parameter is missing')
        self.DAYS = self.getParam('config.num_of_days', None, 'Number of days parameter is missing')
        self.FILTERQUERY = self.getParam('config.filter_expression', ' ', 'Splunk Search query')
        self.SKIP_AUTH = self.getParam('config.skip_auth', False, 'Skip auth parameter is missing')

        if self.getParam('config.sourcetype', None) is not None:
            self.SOURCE = self.getParam('config.sourcetype', None)
            self.source_or_index = "sourcetype"
        elif self.getParam('config.index', None) is not None:
            self.SOURCE = self.getParam('config.index', None)
            self.source_or_index = "index"
        else:
            self.error("You must specify either a sourcetype or an index to search on. "
                       "You may also specify '*' for all sourcetypes/indexes.")

        self.base_search_query = 'search {0} {1}={2}'

    # Create a Service instance and log in
    def splunk_connect(self):
        try:
            self.service = client.connect(
                host=self.HOST,
                port=self.PORT,
                username=self.USERNAME,
                password=self.PASSWORD,
                basic=self.SKIP_AUTH)
        except Exception as e:
            self.unexpectedError(e)

    def splunk_url_search(self, url):
        try:
            regex = re.compile(r"(?::\/\/)([^\/|\?|\&|\$|\+|\,|\:|\;|\=|\@|\#]+)")
            match = regex.search(url)
            domain = match.group(1)
        except Exception as e:
            self.error('Malformed URL. Could not extract FQDN from URL.' + str(e))
        searchquery_normal = self.base_search_query.format(domain, self.source_or_index ,self.SOURCE) + self.FILTERQUERY
        kwargs_normalsearch = {"exec_mode": "normal", "earliest_time": "-{0}d".format(self.DAYS),
                               "latest": "now", "output_mode": "xml"}
        job = self.service.jobs.create(searchquery_normal, **kwargs_normalsearch)
        # # A normal search returns the job's SID right away, so we need to poll for completion
        while True:
            while not job.is_ready():
                pass
            stats = {"isDone": job["isDone"]}
            if stats["isDone"] == "1":
                break
            sleep(2)
        # Get the results and display them
        finalResult = {}
        index = 0
        for result in results.ResultsReader(job.results()):
            finalResult[index] = result
            index += 1
        finalResult["length"] = index

        searchquery_formatted = searchquery_normal.replace("\/\"", "")
        finalResult["search_query"] = urllib.parse.quote_plus(searchquery_formatted, safe=';/?:@&=+$,"$#@=?%^Q^$')

        job.cancel()

        self.report(finalResult)

    def splunk_domain_search(self, domain):
        searchquery_normal = self.base_search_query.format(domain, self.source_or_index ,self.SOURCE) + self.FILTERQUERY
        kwargs_normalsearch = {"exec_mode": "normal", "earliest_time": "-{0}d".format(self.DAYS), "latest":"now" ,"output_mode": "xml"}
        job = self.service.jobs.create(searchquery_normal, **kwargs_normalsearch)
        # # A normal search returns the job's SID right away, so we need to poll for completion
        while True:
            while not job.is_ready():
                pass
            stats = {"isDone": job["isDone"]}
            if stats["isDone"] == "1":
                break
            sleep(2)
        # Get the results and display them
        final_result = {}
        index = 0
        for result in results.ResultsReader(job.results()):
            final_result[index] = result
            index += 1
        final_result["length"] = index

        searchquery_formatted = searchquery_normal.replace("\/\"", "")
        final_result["search_query"] = urllib.parse.quote_plus(searchquery_formatted, safe=';/?:@&=+$,"$#@=?%^Q^$')

        job.cancel()

        self.report(final_result)

    def splunk_ip_search(self, ipaddr):
        searchquery_normal = self.base_search_query.format(ipaddr, self.source_or_index, self.SOURCE) + self.FILTERQUERY
        kwargs_normalsearch = {"exec_mode": "normal", "earliest_time": "-{0}d".format(self.DAYS),
                               "latest": "now", "output_mode": "xml"}
        job = self.service.jobs.create(searchquery_normal, **kwargs_normalsearch)
        # # A normal search returns the job's SID right away, so we need to poll for completion
        while True:
            while not job.is_ready():
                pass
            stats = {"isDone": job["isDone"]}

            if stats["isDone"] == "1":
                break
            sleep(2)
        # Get the results and display them
        final_result = {}
        index = 0
        for result in results.ResultsReader(job.results()):
            final_result[index] = result
            index += 1
        final_result["length"] = index

        searchquery_formatted = searchquery_normal.replace("\/\"", "")
        final_result["search_query"] = urllib.parse.quote_plus(searchquery_formatted, safe=';/?:@&=+$,"$#@=?%^Q^$')

        job.cancel()

        self.report(final_result)

    def splunk_generic_search(self, searchparam):
        searchquery_normal = self.base_search_query.format(searchparam, self.source_or_index ,self.SOURCE) + self.FILTERQUERY
        kwargs_normalsearch = {"exec_mode": "normal", "earliest_time": "-{0}d".format(self.DAYS), "latest": "now",
                               "output_mode": "xml"}
        job = self.service.jobs.create(searchquery_normal, **kwargs_normalsearch)
        # # A normal search returns the job's SID right away, so we need to poll for completion
        while True:
            while not job.is_ready():
                pass
            stats = {"isDone": job["isDone"]}

            if stats["isDone"] == "1":
                break
            sleep(2)
        # Get the results and display them
        final_result = {}
        index = 0
        for result in results.ResultsReader(job.results()):
            final_result[index] = result
            index += 1
        final_result["length"] = index

        searchquery_formatted = searchquery_normal.replace("\/\"", "")
        final_result["search_query"] = urllib.parse.quote_plus(searchquery_formatted, safe=';/?:@&=+$,"$#@=?%^Q^$')

        job.cancel()

        self.report(final_result)

    def summary(self, raw):
        taxonomies = []
        predicate = "Hits"
        value = "\"0\""
        result = {
            "has_result": True
        }

        if self.data_type == "domain" or self.data_type == "url":
            namespace = "Splunk_Web_Proxy_Logs_{0}_days".format(self.DAYS)
            result["length"] = raw["length"]
            if result["length"] > 0:
                level = "suspicious"
                value = "\"{}\"".format(result["length"])
            else:
                level = "safe"
        else:
            namespace = "Splunk_{0}".format(self.SOURCE)
            result["length"] = raw["length"]
            if result["length"] > 0:
                level = "info"
                value = "\"{}\"".format(result["length"])
            else:
                level = "safe"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)
        if self.service == 'search':
            if self.data_type == 'url':
                data = self.getParam('data', None, 'Data is missing')
                self.splunk_connect()
                self.splunk_url_search(data)
            elif self.data_type == 'domain':
                data = self.getParam('data', None, 'Data is missing')
                self.splunk_connect()
                self.splunk_domain_search(data)
            elif self.data_type == 'ip':
                data = self.getParam('data', None, 'Data is missing')
                self.splunk_connect()
                self.splunk_ip_search(data)
            elif self.data_type != 'file':
                data = self.getParam('data', None, 'Data is missing')
                self.splunk_connect()
                self.splunk_generic_search(data)
            else:
                self.error('Invalid Datatype')
        else:
            self.error('Invalid service')


if __name__ == '__main__':
    Splunk().run()
