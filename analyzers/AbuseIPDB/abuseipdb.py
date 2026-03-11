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

    def _is_cidr(self, value):
        """Check if value is a CIDR range (contains /)"""
        return "/" in value

    def _check_single_ip(self, ip, days_to_check, headers):
        """Check a single IP address using the /check endpoint"""
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "maxAgeInDays": days_to_check,
            "verbose": "True",
            "ipAddress": ip,
        }
        response = requests.get(url, headers=headers, params=params)

        if not (200 <= response.status_code < 300):
            self.error(f"Unable to query AbuseIPDB API\n{response.text}")

        json_response = response.json()
        response_list = (
            json_response
            if isinstance(json_response, list)
            else [json_response]
        )
        for resp in response_list:
            if "reports" in resp["data"]:
                categories_strings = []
                for item in resp["data"]["reports"]:
                    item["categories_strings"] = []
                    for category in item["categories"]:
                        category_as_str = self.extract_abuse_ipdb_category(category)
                        item["categories_strings"].append(category_as_str)
                        if category_as_str not in categories_strings:
                            categories_strings.append(category_as_str)
                resp["categories_strings"] = categories_strings

                reports = resp["data"].get("reports") or []

                # reporter geography
                cc_counts = Counter()
                for r in reports:
                    code = (r.get("reporterCountryCode") or "??").upper()
                    name = r.get("reporterCountryName") or code
                    cc_counts[(code, name)] += 1
                resp["reporting_countries"] = [
                    {"code": code, "name": name, "count": cnt}
                    for (code, name), cnt in cc_counts.most_common(6)
                ]

                # category frequency
                cat_counts = Counter()
                for r in reports:
                    for c in (r.get("categories_strings") or []):
                        cat_counts[c] += 1
                resp["category_counts"] = [
                    {"category": k, "count": v} for k, v in cat_counts.most_common(6)
                ]

                # freshness windows
                now = datetime.now(timezone.utc)
                last_24h = 0
                last_7d = 0
                for r in reports:
                    dt = self._parse_datetime(r.get("reportedAt"))
                    if not dt:
                        continue
                    if (now - dt).total_seconds() <= 24 * 3600:
                        last_24h += 1
                    if (now - dt).total_seconds() <= 7 * 24 * 3600:
                        last_7d += 1

                resp["freshness"] = {"last24h": last_24h, "last7d": last_7d}

        return {"values": response_list, "query_type": "check"}

    def _check_block(self, network, days_to_check, headers):
        """Check a CIDR block using the /check-block endpoint"""
        url = "https://api.abuseipdb.com/api/v2/check-block"
        params = {
            "maxAgeInDays": days_to_check,
            "network": network,
        }
        response = requests.get(url, headers=headers, params=params)

        if not (200 <= response.status_code < 300):
            self.error(f"Unable to query AbuseIPDB API\n{response.text}")

        json_response = response.json()
        data = json_response.get("data", {})

        # Calculate summary statistics for the block
        reported_addresses = data.get("reportedAddress") or []
        total_reports = sum(addr.get("numReports", 0) for addr in reported_addresses)
        max_score = max(
            (addr.get("abuseConfidenceScore", 0) for addr in reported_addresses),
            default=0
        )

        # Freshness for block (based on mostRecentReport)
        now = datetime.now(timezone.utc)
        last_24h = 0
        last_7d = 0
        for addr in reported_addresses:
            dt = self._parse_datetime(addr.get("mostRecentReport"))
            if not dt:
                continue
            if (now - dt).total_seconds() <= 24 * 3600:
                last_24h += 1
            if (now - dt).total_seconds() <= 7 * 24 * 3600:
                last_7d += 1

        # Country statistics
        cc_counts = Counter()
        for addr in reported_addresses:
            code = (addr.get("countryCode") or "??").upper()
            cc_counts[code] += 1

        result = {
            "data": data,
            "summary": {
                "networkAddress": data.get("networkAddress"),
                "netmask": data.get("netmask"),
                "minAddress": data.get("minAddress"),
                "maxAddress": data.get("maxAddress"),
                "numPossibleHosts": data.get("numPossibleHosts"),
                "addressSpaceDesc": data.get("addressSpaceDesc"),
                "reportedAddressCount": len(reported_addresses),
                "totalReports": total_reports,
                "maxAbuseConfidenceScore": max_score,
            },
            "freshness": {"last24h": last_24h, "last7d": last_7d},
            "reporting_countries": [
                {"code": code, "count": cnt}
                for code, cnt in cc_counts.most_common(6)
            ],
        }

        return {"values": [result], "query_type": "check-block"}

    def _parse_datetime(self, dt_string):
        """Parse ISO datetime string"""
        if not dt_string:
            return None
        try:
            return datetime.fromisoformat(dt_string.replace("Z", "+00:00"))
        except Exception:
            return None

    def run(self):
        try:
            if self.data_type == "ip":
                api_key = self.get_param(
                    "config.key", None, "Missing AbuseIPDB API key"
                )
                days_to_check = self.get_param("config.days", 30)
                ip = self.get_data()

                headers = {
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Key": api_key,
                    "User-Agent": "strangebee-thehive/1.0",
                }

                if self._is_cidr(ip):
                    result = self._check_block(ip, days_to_check, headers)
                else:
                    result = self._check_single_ip(ip, days_to_check, headers)

                self.report(result)
            else:
                self.notSupported()
        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        if not raw or "values" not in raw or not raw["values"]:
            return {"taxonomies": []}

        query_type = raw.get("query_type", "check")

        if query_type == "check-block":
            return self._summary_check_block(raw)
        else:
            return self._summary_check(raw)

    def _summary_check(self, raw):
        """Generate summary for single IP check"""
        taxonomies = []
        is_whitelisted = False
        data = raw["values"][0].get("data", {})

        if data.get("isWhitelisted", False):
            is_whitelisted = True
            taxonomies.append(
                self.build_taxonomy("info", "AbuseIPDB", "Whitelisted", "True")
            )

        if data.get("isTor", False):
            taxonomies.append(
                self.build_taxonomy("info", "AbuseIPDB", "Tor", "True")
            )

        if "usageType" in data:
            taxonomies.append(
                self.build_taxonomy("info", "AbuseIPDB", "Usage", data["usageType"])
            )

        if "abuseConfidenceScore" in data:
            score = int(data.get("abuseConfidenceScore") or 0)
            level = (
                "malicious" if score >= 75 else ("suspicious" if score > 0 else "safe")
            )
            taxonomies.append(
                self.build_taxonomy(level, "AbuseIPDB", "Score", score)
            )

        total_reports = data.get("totalReports") or 0
        if total_reports > 0:
            level = "info" if is_whitelisted else "malicious"
            taxonomies.append(
                self.build_taxonomy(level, "AbuseIPDB", "Reports", total_reports)
            )
        else:
            taxonomies.append(
                self.build_taxonomy("safe", "AbuseIPDB", "Reports", 0)
            )

        return {"taxonomies": taxonomies}

    def _summary_check_block(self, raw):
        """Generate summary for CIDR block check"""
        taxonomies = []
        summary_data = raw["values"][0].get("summary", {})

        reported_count = summary_data.get("reportedAddressCount", 0)
        total_reports = summary_data.get("totalReports", 0)
        max_score = summary_data.get("maxAbuseConfidenceScore", 0)

        # Max abuse score in the block
        level = (
            "malicious" if max_score >= 75 else ("suspicious" if max_score > 0 else "safe")
        )
        taxonomies.append(
            self.build_taxonomy(level, "AbuseIPDB", "Max Score", max_score)
        )

        # Number of reported IPs in the block
        if reported_count > 0:
            taxonomies.append(
                self.build_taxonomy("suspicious", "AbuseIPDB", "Reported IPs", reported_count)
            )
        else:
            taxonomies.append(
                self.build_taxonomy("safe", "AbuseIPDB", "Reported IPs", 0)
            )

        # Total reports across the block
        if total_reports > 0:
            taxonomies.append(
                self.build_taxonomy("info", "AbuseIPDB", "Total Reports", total_reports)
            )

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        if not raw or "values" not in raw or not raw["values"]:
            return artifacts

        query_type = raw.get("query_type", "check")

        if query_type == "check-block":
            return self._artifacts_check_block(raw)
        else:
            return self._artifacts_check(raw)

    def _artifacts_check(self, raw):
        """Extract artifacts from single IP check"""
        artifacts = []
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

        for d in sorted(domains_out):
            artifacts.append(self.build_artifact("domain", d, tags=["AbuseIPDB"]))

        for h in sorted(hostnames_out):
            artifacts.append(self.build_artifact("fqdn", h, tags=["AbuseIPDB"]))

        return artifacts

    def _artifacts_check_block(self, raw):
        """Extract artifacts from CIDR block check (reported IPs)"""
        artifacts = []
        ips_out = set()

        for entry in raw["values"]:
            data = entry.get("data") or {}
            for addr in data.get("reportedAddress") or []:
                ip = addr.get("ipAddress")
                if ip:
                    ips_out.add(ip)

        for ip in sorted(ips_out):
            artifacts.append(self.build_artifact("ip", ip, tags=["AbuseIPDB"]))

        return artifacts


if __name__ == "__main__":
    AbuseIPDBAnalyzer().run()
