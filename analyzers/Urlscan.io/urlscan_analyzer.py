#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from urlscan import Urlscan, UrlscanException
import jmespath
import time
import re


def process_result(full_result, rtype, filter):
    # filter = "data.requests[].request.redirectResponse | @[?headers.location == 'https://google.com/404/'].url | [0]"
    match = None
    if rtype == "jmespath":
        match = jmespath.search(filter, full_result)
    elif rtype == "pattern":
        re1 = re.compile(filter)
        for url in full_result['data']['lists']['urls']:
            matching = re1.match(url)
            if matching:
                match = matching.group(0)

    return match


class UrlscanAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        if self.service == 'scan' or self.service == 'search' or self.service == 'search_subrequests':
            self.api_key = self.get_param('config.key', None, 'Missing URLScan API key')

    def search(self, indicator, api_key, search_after=None):
        """
        Searches for a website using the indicator
        :param indicator: domain, ip, hash, url
        :type indicator: str
        :type api_key: str
        :type search_after: str
        :return: dict
        """
        res = Urlscan(indicator, api_key).search(search_after=search_after)
        return res

    def result(self, result_id, api_key):
        """
        Searches for a website using the indicator
        :param indicator: domain, ip, hash, url
        :type result_id: str
        :type api_key: str
        :return: dict
        """
        res = Urlscan(result_id, api_key).result(result_id)
        return res

    def scan(self, indicator):
        """
        Scans a website for indicators
        :param indicator: url
        :type indicator: str
        :return: dict
        """
        res = Urlscan(indicator).scan(self.api_key)
        return res

    def run(self):
        targets = ['ip', 'domain', 'hash', 'url', 'other']
        if self.data_type == 'url':
            query = '"{}"'.format(self.get_data())
        else:
            query = self.get_data()

        if self.service == 'search':
            try:
                if self.data_type in targets:
                    search_after = self.get_param('parameters.search_after', None, None)
                    self.report({
                        'type': self.data_type,
                        'query': query + ". Search after: " + str(search_after),
                        'indicator': self.search(query, self.api_key, search_after=search_after)
                    })
            except UrlscanException as err:
                self.error(str(err))

        if self.service == 'search_subrequests':
            try:
                if self.data_type in targets:
                    filter_type = self.get_param('parameters.type', "pattern", None)
                    filter = self.get_param('parameters.filter', None, None)
                    search_json = self.search(query, self.api_key)
                    matches = []

                    for result in search_json["results"]:
                        scan_date = result['task']['time']
                        res = process_result(result, filter_type, filter)
                        matches.append({'scan_date': scan_date, 'url': res})
                        time.sleep(0.8)

                    self.report({
                        'type': self.data_type,
                        'query': f"Search `{filter}` on {query}.",
                        'matches': matches
                    })
            except UrlscanException as err:
                self.error(str(err))

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "urlscan.io"
        predicate = "Search"

        total = raw["indicator"]["total"]
        if total <= 1:
            level = 'suspicious' if total == 1 else 'info'
            value = total
            taxonomies.append(self.build_taxonomy(
                level, namespace, predicate, value))
        else:
            level = 'suspicious'
            value = total
            taxonomies.append(self.build_taxonomy(
                level, namespace, predicate, value))

        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    UrlscanAnalyzer().run()
