#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from urldna import UrlDNA, UrlDNAException


class UrlDNAAnalyzer(Analyzer):
    """Analyzer for performing UrlDNA operations."""

    def __init__(self):
        """
        Initializes the analyzer with configuration parameters.
        """
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.api_key = self.get_param('config.key', None, 'Missing UrlDNA API key')
        self.device = self.get_param('config.device')
        self.user_agent = self.get_param('config.user_agent')
        self.viewport_width = self.get_param('config.viewport_width')
        self.viewport_height = self.get_param('config.viewport_height')
        self.waiting_time = self.get_param('config.waiting_time')
        self.private_scan = self.get_param('config.private_scan')
        self.scanned_from = self.get_param('config.scanned_from')

    def new_scan(self, indicator):
        """
        Scans a website or resource for indicators.

        :param indicator: The URL to scan.
        :return: A dictionary containing the scan results.
        """
        try:
            urldna = UrlDNA(indicator)
            return urldna.new_scan(self.api_key, self.device, self.user_agent, self.viewport_width,
                                   self.viewport_height, self.waiting_time, self.private_scan, self.scanned_from)
        except UrlDNAException as exc:
            self.error(f"Error during urlDNA scan: {exc}")
        except Exception as exc:
            self.error(f"Unexpected error: {exc}")

    def search(self, query):
        """
        Performs a search query on the UrlDNA API.

        :param query: The query string.
        :return: A dictionary containing the search results.
        """
        try:
            urldna = UrlDNA(query, self.data_type)
            return urldna.search(self.api_key)
        except UrlDNAException as exc:
            self.error(f"Error during search: {exc}")
        except Exception as exc:
            self.error(f"Unexpected error: {exc}")

    def run(self):
        """
        Executes the analyzer logic based on the configured service and data type.
        """
        if not self.service or not self.data_type:
            self.error('Service or data_type is missing.')
            raise ValueError('Invalid configuration.')

        if self.service == 'new_scan' and self.data_type == 'url':
            indicator = self.get_data()
            try:
                result = self.new_scan(indicator)
                self.report({
                    'type': self.data_type,
                    'query': indicator,
                    'service': self.service,
                    'indicator': result
                })
            except Exception as exc:
                self.error(f"Run failed: {exc}")
        elif self.service == 'search':
            query = self.get_data()
            try:
                result = self.search(query)
                self.report({
                    'type': self.data_type,
                    'query': query,
                    'service': self.service,
                    'indicator': result
                })
            except Exception as exc:
                self.error(f"Run failed: {exc}")
        else:
            self.error('Invalid service or unsupported data type.')
            raise ValueError('Unsupported service or data type.')

    def summary(self, raw):
        """
        Generates a summary based on the scan results.

        :param raw: The raw scan data.
        :return: A dictionary containing summary taxonomies.
        """
        taxonomies = []
        level = "info"
        namespace = "urlDNA.io"
        predicate = "Scan" if raw["service"] == 'new_scan' else "Search"

        indicator = raw.get("indicator", {})
        if predicate == "Search":
            total = len(indicator)
            value = f"{total} result{'s' if total != 1 else ''}" if total > 0 else "No results found"
        else:
            malicious = indicator.get("malicious", {})
            is_malicious = malicious.get("malicious", False)
            threat_type = malicious.get("threat", "Unknown")
            level = 'malicious' if is_malicious else 'info'
            value = f"Malicious: {is_malicious}, Threat Type: {threat_type}"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    UrlDNAAnalyzer().run()
