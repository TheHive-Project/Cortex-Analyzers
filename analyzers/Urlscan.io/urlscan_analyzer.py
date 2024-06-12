#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from urlscan import Urlscan, UrlscanException


class UrlscanAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        if self.service == 'scan':
            self.api_key = self.get_param('config.key', None, 'Missing URLScan API key')

    def search(self, indicator):
        """
        Searches for a website using the indicator
        :param indicator: domain, ip, hash, url
        :type indicator: str
        :return: dict
        """
        res = Urlscan(indicator).search()
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
        if self.service == 'scan':
            if self.data_type in ['domain', 'url', 'fqdn']:
                query = '"{}"'.format(self.get_data())
                try:
                    self.report({
                        'type': self.data_type,
                        'query': query,
                        'service': self.service,
                        'indicator': self.scan(query)
                    })
                except UrlscanException as err:
                    self.error(str(err))
            else:
                self.error('Invalid data type. URL expected')
        elif self.service == 'get':
            targets = ['ip', 'domain', 'fqdn', 'hash', 'url']
            if self.data_type == 'url':
                query = '"{}"'.format(self.get_data())
            else:
                query = self.get_data()

            try:
                if self.data_type in targets:
                    self.report({
                        'type': self.data_type,
                        'query': query,
                        'service': self.service,
                        'indicator': self.search(query)
                    })
            except UrlscanException as err:
                self.error(str(err))
        else:
            self.error('Invalid service')


    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "urlscan.io"
        predicate = "Search" if raw["service"] == 'get' else "Scan"
        
        if predicate == "Search":
            total = raw["indicator"]["total"]
            if total <= 1:
                level = 'suspicious' if total == 1 else 'info'
                value = "{} result".format(total)
                taxonomies.append(self.build_taxonomy(
                    level, namespace, predicate, value))
            else:
                level = 'suspicious'
                value = "{} results".format(total)
                taxonomies.append(self.build_taxonomy(
                    level, namespace, predicate, value))
        else:
            score = raw["indicator"]["verdicts"]["overall"]["score"]
            value = "Overall Score:{}".format(score)
            malicious = raw["indicator"]["verdicts"]["overall"]["malicious"]
            if malicious:
                level = 'malicious'
            elif score > 0:
                level = 'suspicious'
            taxonomies.append(self.build_taxonomy(
                    level, namespace, predicate, value))

        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    UrlscanAnalyzer().run()
