#!/usr/bin/env python3

import requests
from collections import Counter
from itertools import chain

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
        return mapping.get(str(category_number), "unknown category")

    def run(self):

        try:
            if self.data_type == "ip":
                api_key = self.get_param(
                    "config.key", None, "Missing AbuseIPDB API key"
                )
                days_to_check = self.get_param("config.days", 30)
                ip = self.get_data()

                headers = {"Accept": "application/json", "key": api_key}
                querystring = {"ipAddress": ip, "maxAgeInDays": days_to_check}
                url = "https://www.abuseipdb.com/api/v2/check?verbose"
                response = requests.get(url, headers=headers, params=querystring)
                if not (200 <= response.status_code < 300):
                    self.error(
                        "Unable to query AbuseIPDB API\n{}".format(response.text)
                    )
                json_response = response.json()["data"]

                # count reports category
                categories_count = Counter(
                    chain.from_iterable(
                        [
                            report.get("categories", [])
                            for report in json_response.get("reports", [])
                        ]
                    )
                ).most_common()

                json_response["categories"] = []
                for category, count in categories_count:
                    json_response["categories"].append(
                        {
                            "category": self.extract_abuse_ipdb_category(category),
                            "count": count,
                        }
                    )

                # count reports nationality
                nationalities_count = Counter(
                    [
                        report.get("reporterCountryCode", [])
                        for report in json_response.get("reports", [])
                    ]
                ).most_common()

                json_response["nationalities"] = []
                for nationality, count in nationalities_count:
                    json_response["nationalities"].append(
                        {"nationality": nationality, "count": count,}
                    )

                del json_response["reports"]

                self.report({"values": json_response})
            else:
                self.notSupported()
        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        taxonomies = []
        if raw.get("values", {}).get("totalReports", 0) > 0:
            taxonomies.append(
                self.build_taxonomy(
                    "malicious",
                    "AbuseIPDB",
                    "Records",
                    raw["values"]["totalReports"],
                )
            )
        else:
            taxonomies.append(self.build_taxonomy("safe", "AbuseIPDB", "Records", 0))

        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    AbuseIPDBAnalyzer().run()
