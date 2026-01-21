#!/usr/bin/env python3
# encoding: utf-8

import requests
from cortexutils.responder import Responder


class AbuseIPDBResponder(Responder):
    """
    AbuseIPDB Responder - Report malicious IP addresses to AbuseIPDB
    API documentation: https://docs.abuseipdb.com/#report-endpoint
    """

    # Mapping from category ID to name (for display)
    CATEGORIES = {
        "1": "DNS Compromise",
        "2": "DNS Poisoning",
        "3": "Fraud Orders",
        "4": "DDoS Attack",
        "5": "FTP Brute-Force",
        "6": "Ping of Death",
        "7": "Phishing",
        "8": "Fraud VoIP",
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

    # Reverse mapping from category name to ID (for API calls)
    CATEGORY_NAME_TO_ID = {name: id for id, name in CATEGORIES.items()}

    def __init__(self):
        Responder.__init__(self)
        self.api_key = self.get_param("config.key", None, "Missing AbuseIPDB API key")
        self.categories = self.get_param("config.categories", ["Brute Force"])
        self.comment = self.get_param("config.comment", "")
        self.service = self.get_param("config.service", "report")

    def run(self):
        Responder.run(self)

        if self.service == "report":
            self.report_ip()
        else:
            self.error(f"Unknown service: {self.service}")

    def report_ip(self):
        """Report an IP address to AbuseIPDB"""
        data_type = self.get_param("data.dataType", None)

        if data_type != "ip":
            self.error("This responder only supports IP addresses")
            return

        ip_address = self.get_param("data.data", None, "No IP address provided")

        # Ensure categories is a list
        category_list = self.categories if isinstance(self.categories, list) else [self.categories]

        # Validate and translate category names to IDs
        category_ids = []
        invalid_categories = []
        for cat_name in category_list:
            cat_name = cat_name.strip()
            if cat_name in self.CATEGORY_NAME_TO_ID:
                category_ids.append(self.CATEGORY_NAME_TO_ID[cat_name])
            else:
                invalid_categories.append(cat_name)

        if invalid_categories:
            valid_names = ", ".join(self.CATEGORY_NAME_TO_ID.keys())
            self.error(f"Invalid category names: {', '.join(invalid_categories)}. Valid categories are: {valid_names}")
            return

        if not category_ids:
            self.error("At least one category must be specified")
            return

        # Convert category IDs to comma-separated string for API
        categories_str = ",".join(category_ids)

        # Prepare the API request
        url = "https://api.abuseipdb.com/api/v2/report"
        headers = {
            "Accept": "application/json",
            "Key": self.api_key,
            "User-Agent": "strangebee-thehive/1.0",
        }
        payload = {
            "ip": ip_address,
            "categories": categories_str,
        }

        if self.comment:
            # Truncate comment to 1024 characters as per API limit
            payload["comment"] = self.comment[:1024]

        try:
            response = requests.post(url, headers=headers, data=payload)

            if response.status_code == 200:
                result = response.json()
                data = result.get("data", {})

                self.report({
                    "success": True,
                    "message": f"IP {ip_address} reported successfully to AbuseIPDB",
                    "ip_address": data.get("ipAddress", ip_address),
                    "abuse_confidence_score": data.get("abuseConfidenceScore"),
                    "categories_reported": category_list,
                })
            elif response.status_code == 422:
                # Validation error from API
                error_detail = response.json().get("errors", [{}])[0].get("detail", "Validation error")
                self.error(f"AbuseIPDB validation error: {error_detail}")
            elif response.status_code == 429:
                self.error("AbuseIPDB rate limit exceeded. Please try again later.")
            elif response.status_code == 401:
                self.error("Invalid AbuseIPDB API key")
            else:
                self.error(f"AbuseIPDB API error (HTTP {response.status_code}): {response.text}")

        except requests.exceptions.RequestException as e:
            self.error(f"Network error while contacting AbuseIPDB: {str(e)}")

    def operations(self, raw):
        """Add a tag to the artifact after successful reporting"""
        operations = []
        if raw.get("success"):
            operations.append(
                self.build_operation("AddTagToArtifact", tag="AbuseIPDB:reported")
            )
        return operations


if __name__ == "__main__":
    AbuseIPDBResponder().run()
