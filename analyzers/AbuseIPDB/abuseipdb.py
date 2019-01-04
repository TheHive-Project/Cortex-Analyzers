#!/usr/bin/env python3

import requests

from cortexutils.analyzer import Analyzer


class AbuseIPDBAnalyzer(Analyzer):
    """
    AbuseIPDB API docs: https://www.abuseipdb.com/api
    """

    @staticmethod
    def extract_abuse_ipdb_category(category_number):
        # Reference: https://www.abuseipdb.com/categories
        mapping = {
            "3": "Fraud Orders",
            "4": "DDOS Attack",
            "5": "FTP Brute-Force",
            "6": "Ping of Death",
            "7": "Phishing",
            "8": "Fraud VOIP",
            "9": "Open Proxy",
            "10": "Web Spam",
            "11": "Email Spam",
            "12": "Blog Spam",
            "13": "VPN IP",
            "14": "Port Scan",
            "15": "Hacking",
            "16": "SQL Injection",
            "17": "Spoofing",
            "18": "Brute Force",
            "19": "Bad Web Bot",
            "20": "Exploited Host",
            "21": "Web App Attack",
            "22": "SSH",
            "23": "IoT Targeted",
        }
        return mapping.get(str(category_number), 'unknown category')

    def run(self):

        try:
            if self.data_type == "ip":
                api_key = self.get_param('config.key', None, 'Missing AbuseIPDB API key')
                days_to_check = self.get_param('config.days', 30)
                ip = self.get_data()
                url = 'https://www.abuseipdb.com/check/{}/json?key={}&days={}' \
                      ''.format(ip, api_key, days_to_check)
                response = requests.get(url)
                if not (200 <= response.status_code < 300):
                    self.error('Unable to query AbuseIPDB API\n{}'.format(response.text))
                json_response = response.json()
                # this is because in case there's only one result, the api gives back a list instead of a dict
                response_list = json_response if isinstance(json_response, list) else [json_response]
                for found in response_list:
                    if 'category' in found:
                        categories_strings = []
                        for category in found['category']:
                            categories_strings.append(self.extract_abuse_ipdb_category(category))
                        found['categories_strings'] = categories_strings
                self.report({'values': response_list})
            else:
                self.notSupported()
        except Exception as e:
            self.error('Run failed\n Error:{}'.format(e))

    def summary(self, raw):

        try:
            taxonomies = []
            if raw:
                taxonomies.append(self.build_taxonomy('malicious', 'AbuseIPDB', 'Records found', 'None'))
            else:
                taxonomies.append(self.build_taxonomy('safe', 'AbuseIPDB', 'Records not found', 'None'))

            return {"taxonomies": taxonomies}

        except Exception as e:
            self.error('Summary failed\n Error:{}'.format(e))


if __name__ == '__main__':
    AbuseIPDBAnalyzer().run()
