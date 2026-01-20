#!/usr/bin/env python3

import requests
from requests.exceptions import RequestException
from collections import Counter
from datetime import datetime, timezone

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
        return mapping.get(str(category_number), "Unknown Category")

    def run(self):

        try:
            if self.data_type == "ip":
                api_key = self.get_param(
                    "config.key", None, "Missing AbuseIPDB API key"
                )

                days_to_check = self.get_param("config.days", 30)
                ip = self.get_data()

                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Key": "%s" % api_key,
                }
                params = {
                    "maxAgeInDays": days_to_check,
                    "verbose": "True",
                    "ipAddress": ip,
                }
                response = requests.get(url, headers=headers, params=params)

                if not (200 <= response.status_code < 300):
                    self.error(
                        "Unable to query AbuseIPDB API\n{}".format(response.text)
                    )

                json_response = response.json()
                # this is because in case there's only one result, the api gives back a list instead of a dict
                response_list = (
                    json_response
                    if isinstance(json_response, list)
                    else [json_response]
                )
                for response in response_list:
                    if "reports" in response["data"]:
                        categories_strings = []
                        for item in response["data"]["reports"]:
                            item["categories_strings"] = []
                            for category in item["categories"]:
                                category_as_str = self.extract_abuse_ipdb_category(
                                    category
                                )
                                item["categories_strings"].append(category_as_str)
                                if category_as_str not in categories_strings:
                                    categories_strings.append(category_as_str)
                        response["categories_strings"] = categories_strings
                        
                        reports = response["data"].get("reports") or []

                        # reporter geography
                        cc_counts = Counter()
                        for r in reports:
                            code = (r.get("reporterCountryCode") or "??").upper()
                            name = r.get("reporterCountryName") or code
                            cc_counts[(code, name)] += 1
                        response["reporting_countries"] = [
                            {"code": code, "name": name, "count": cnt}
                            for (code, name), cnt in cc_counts.most_common(6)  # top 6
                        ]

                        # category frequency
                        cat_counts = Counter()
                        for r in reports:
                            for c in (r.get("categories_strings") or []):
                                cat_counts[c] += 1
                        response["category_counts"] = [{"category": k, "count": v} for k, v in cat_counts.most_common(6)]

                        # freshness windows (simple counts)
                        def to_dt(x):
                            try:
                                return datetime.fromisoformat(x.replace("Z", "+00:00"))
                            except Exception:
                                return None

                        now = datetime.now(timezone.utc)
                        last_24h = 0
                        last_7d = 0
                        for r in reports:
                            dt = to_dt(r.get("reportedAt"))
                            if not dt:
                                continue
                            if (now - dt).total_seconds() <= 24*3600:
                                last_24h += 1
                            if (now - dt).total_seconds() <= 7*24*3600:
                                last_7d += 1

                        response["freshness"] = {"last24h": last_24h, "last7d": last_7d}


                self.report({"values": response_list})
            else:
                self.notSupported()
        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        taxonomies = []  # level, namespace, predicate, value

        is_whitelisted = False
        data = {}
        if raw and "values" in raw:
            data = raw["values"][0]["data"]
        else:
            return {"taxonomies": []}

        if data.get("isWhitelisted", False):
            is_whitelisted = True
            taxonomies.append(
                self.build_taxonomy("info", "AbuseIPDB", "Is Whitelist", "True")
            )

        if data.get("isTor", False):
            taxonomies.append(
                self.build_taxonomy("info", "AbuseIPDB", "Is Tor", "True")
            )

        if "usageType" in data:
            taxonomies.append(
                self.build_taxonomy(
                    "info", "AbuseIPDB", "Usage Type", data["usageType"]
                )
            )

        if "abuseConfidenceScore" in data:
            score = int(data.get("abuseConfidenceScore") or 0)
            level = (
                "malicious" if score >= 75 else ("suspicious" if score > 0 else "safe")
            )
            taxonomies.append(
                self.build_taxonomy(level, "AbuseIPDB", "Abuse Confidence Score", score)
            )

        if (data.get("totalReports") or 0) > 0:
            if is_whitelisted:
                taxonomies.append(
                    self.build_taxonomy(
                        "info", "AbuseIPDB", "Records", data["totalReports"]
                    )
                )
            else:
                taxonomies.append(
                    self.build_taxonomy(
                        "malicious", "AbuseIPDB", "Records", data["totalReports"]
                    )
                )
        else:
            taxonomies.append(self.build_taxonomy("safe", "AbuseIPDB", "Records", 0))

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        if not raw or "values" not in raw or not raw["values"]:
            return artifacts

        domains_out = set()
        hostnames_out = set()

        for entry in raw["values"]:
            data = entry.get("data") or {}

            # base domain 
            base = (data.get("domain") or "").strip().rstrip(".").lower()
            if base:
                domains_out.add(base)

            # hostnames -> fqdn/hostname artifacts
            for h in data.get("hostnames") or []:
                h = (h or "").strip().rstrip(".").lower()
                if h:
                    hostnames_out.add(h)

        # domains
        for d in sorted(domains_out):
            artifacts.append(self.build_artifact("domain", d, tags=["AbuseIPDB"]))

        # hostnames as fqdn
        for h in sorted(hostnames_out):
            artifacts.append(self.build_artifact("fqdn", h, tags=["AbuseIPDB"]))

        return artifacts


if __name__ == "__main__":
    AbuseIPDBAnalyzer().run()
