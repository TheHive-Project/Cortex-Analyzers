#!/usr/bin/env python3

import requests

from cortexutils.analyzer import Analyzer


class AbuseIPDBAnalyzer(Analyzer):
    """
    AbuseIPDB APIv2 docs: https://docs.abuseipdb.com/
    """

    @staticmethod
    def extract_abuse_ipdb_category(category_number):
        # Reference: https://www.abuseipdb.com/categories
        mapping = {
            "1": "DNS Compromise",
            "2": "DNS Poisoning",
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
        return mapping.get(str(category_number), 'Unknown Category')

    def run(self):

        try:
            if self.data_type == "ip":
                api_key = self.get_param('config.key', None, 'Missing AbuseIPDB API key')

                days_to_check = self.get_param('config.days', 30)
                ip = self.get_data()

                url = 'https://api.abuseipdb.com/api/v2/check'
                headers = {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', 'Key': '%s' % api_key }
                params = {'maxAgeInDays': days_to_check, 'verbose': 'True', 'ipAddress': ip}
                response = requests.get(url, headers = headers, params = params)

                if not (200 <= response.status_code < 300):
                    self.error('Unable to query AbuseIPDB API\n{}'.format(response.text))

                json_response = response.json()
                # this is because in case there's only one result, the api gives back a list instead of a dict
                response_list = json_response if isinstance(json_response, list) else [json_response]
                for response in response_list:
                    if 'reports' in response["data"]:
                        categories_strings = []
                        for item in response["data"]["reports"]:
                            item['categories_strings'] = []
                            for category in item["categories"]:
                                category_as_str = self.extract_abuse_ipdb_category(category)
                                item['categories_strings'].append(category_as_str)
                                if category_as_str not in categories_strings:
                                    categories_strings.append(category_as_str)
                        response['categories_strings'] = categories_strings

                self.report({'values': response_list})
            else:
                self.notSupported()
        except Exception as e:
            self.unexpectedError(e)


    def summary(self, raw):
        taxonomies = []  # level, namespace, predicate, value

        is_whitelisted = False
        data = {}
        if raw and 'values' in raw:
            data = raw['values'][0]['data']
        else:
            return {'taxonomies': []}

        if data.get('isWhitelisted', False):
            is_whitelisted = True
            taxonomies.append(self.build_taxonomy('info', 'AbuseIPDB', 'Is Whitelist', 'True'))

        if data.get('isTor', False):
            taxonomies.append(self.build_taxonomy('info', 'AbuseIPDB', 'Is Tor', 'True'))

        if 'usageType' in data:
            taxonomies.append(self.build_taxonomy('info', 'AbuseIPDB', 'Usage Type', data['usageType']))

        if 'abuseConfidenceScore' in data:
            if data['abuseConfidenceScore'] > 0:
                taxonomies.append(self.build_taxonomy('suspicious', 'AbuseIPDB', 'Abuse Confidence Score', data['abuseConfidenceScore']))
            else:
                taxonomies.append(self.build_taxonomy('safe', 'AbuseIPDB', 'Abuse Confidence Score', 0))

        if data['totalReports'] > 0 :
            if is_whitelisted:
                taxonomies.append(self.build_taxonomy('info', 'AbuseIPDB', 'Records', data['totalReports']))
            else:
                taxonomies.append(self.build_taxonomy('malicious', 'AbuseIPDB', 'Records', data['totalReports']))
        else:
            taxonomies.append(self.build_taxonomy('safe', 'AbuseIPDB', 'Records', 0))

        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    AbuseIPDBAnalyzer().run()
