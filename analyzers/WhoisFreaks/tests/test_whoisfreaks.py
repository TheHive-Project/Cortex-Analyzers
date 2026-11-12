#!/usr/bin/env python3
# encoding: utf-8
"""Tests of the WhoisFreaks analyzer: every flavor's happy path, the retry, billing and
redirect rules, error mapping and malformed responses. The HTTP layer is a fake session,
so no request leaves the machine. Run from the analyzer folder, with requirements.txt
installed:

    python -m unittest discover -s tests -v
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
import warnings
from datetime import date, timedelta
from unittest import mock
from urllib.parse import urlparse

import requests
from requests.structures import CaseInsensitiveDict
from urllib3.exceptions import MaxRetryError, NewConnectionError

ANALYZER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ANALYZER)

import whoisfreaks  # noqa: E402
import whoisfreaks_api  # noqa: E402

KEY = "test-key-0123456789abcdef"
RECENT = (date.today() - timedelta(days=5)).isoformat()


class FakeResponse(object):
    def __init__(self, status=200, body=None, raw=None, headers=None):
        self.status_code = status
        self.headers = CaseInsensitiveDict(headers or {})
        self.text = raw if raw is not None else json.dumps(body)

    def json(self):
        return json.loads(self.text)


def whois_record(domain):
    if "unregistered" in domain:
        return {"status": True, "domain_name": domain, "domain_registered": "no"}
    return {
        "status": True,
        "domain_name": domain,
        "domain_registered": "yes",
        "create_date": RECENT if domain.startswith("new") else "2019-01-01",
        "domain_registrar": {"registrar_name": "NAMECHEAP INC"},
        "registrant_contact": {"email_address": "REDACTED FOR PRIVACY"},
        "technical_contact": {"email_address": "tech@" + domain},
        "name_servers": ["ns1.example-dns.net", "NS2.EXAMPLE-DNS.NET."],
    }


DNS_RECORDS = [
    {"dnsType": "A", "address": "93.184.216.34"},
    {"dnsType": "A", "address": "10.1.2.3"},
    {"dnsType": "NS", "singleName": "ns1.example-dns.net."},
    {"dnsType": "MX", "target": "mx.example-mail.net.", "priority": 10},
]


def security_v2(ip):
    sec = {
        "threat_score": 5,
        "is_tor": False,
        "is_vpn": False,
        "is_proxy": False,
        "is_residential_proxy": False,
        "is_relay": False,
        "is_bot": False,
        "is_known_good_bot": False,
        "is_spam": False,
        "is_known_attacker": False,
    }
    if ip == "185.220.101.1":
        sec.update(threat_score=90, is_tor=True, is_known_attacker=True)
    return {"ip": ip, "security": sec, "asn": {"as_number": "AS15169"}}


def default_api(call):
    """Spec-shaped answers of api.whoisfreaks.com for the default runs."""
    path, q, body = call["path"], call["params"] or {}, call["body"] or {}
    page = int(q.get("page", 1))
    if path == "/v2.0/whois/live":
        return FakeResponse(body=whois_record(q["domainName"]))
    if path == "/v2.0/whois/history":
        return FakeResponse(
            body={
                "total_records": "2",
                "whois_domains_historical": [
                    whois_record(q["domainName"]),
                    whois_record(q["domainName"]),
                ],
            }
        )
    if path == "/v2.0/whois/reverse":
        return FakeResponse(
            body={
                "total_Result": 120,
                "total_Pages": 3,
                "whois_domains_historical": [
                    {"domain_name": "rw-p{}-{}.com".format(page, i)} for i in range(2)
                ],
            }
        )
    if path == "/v2.0/bulkwhois/live":
        return FakeResponse(
            body={"bulk_whois_response": [whois_record(d) for d in body["domainNames"]]}
        )
    if path == "/v2.0/dns/live":
        if "ipAddress" in q:
            return FakeResponse(
                body={
                    "status": True,
                    "ipAddress": q["ipAddress"],
                    "dnsRecords": [{"dnsType": "PTR", "singleName": "dns.google."}],
                }
            )
        return FakeResponse(
            body={"status": True, "domainName": q["domainName"], "dnsRecords": DNS_RECORDS}
        )
    if path == "/v2.0/dns/historical":
        return FakeResponse(
            body={
                "totalRecords": 150,
                "totalPages": 2,
                "historicalDnsRecords": [
                    {"queryTime": "2025-01-0{}".format(page), "dnsRecords": DNS_RECORDS}
                ],
            }
        )
    if path == "/v2.1/dns/reverse":
        return FakeResponse(
            body={
                "totalRecords": 250,
                "totalPages": 3,
                "reverseDnsRecords": [
                    {"domainName": "rd-p{}-{}.com".format(page, i)} for i in range(2)
                ],
            }
        )
    if path == "/v2.0/dns/bulk/live":
        out = [
            {"status": True, "domainName": d, "dnsRecords": DNS_RECORDS}
            for d in body.get("domainNames", [])
        ]
        out += [
            {
                "status": True,
                "ipAddress": ip,
                "domainName": "dns.google",
                "dnsRecords": [{"dnsType": "PTR", "singleName": "dns.google."}],
            }
            for ip in body.get("ipAddresses", [])
        ]
        return FakeResponse(body={"bulk_dns_info": out})
    if path == "/v2.0/domain/availability":
        if call["method"] == "GET":
            return FakeResponse(body={"domain": q["domain"], "availability": "AVAILABLE"})
        if "tld" in body:
            return FakeResponse(
                body={
                    "bulk_domain_availability_response": [
                        {
                            "domain": "{}.{}".format(q["domain"], t),
                            "status": True,
                            "availability": "UNAVAILABLE" if t == "net" else "AVAILABLE",
                        }
                        for t in body["tld"]
                    ]
                }
            )
        return FakeResponse(
            body={
                "bulk_domain_availability_response": [
                    {"domain": d, "status": True, "availability": "UNAVAILABLE"}
                    for d in body["domainNames"]
                ]
            }
        )
    if path == "/v3.0/domain/typos":
        n = int(q["pageToken"][-1]) + 1 if q.get("pageToken") else 1
        return FakeResponse(
            body={
                "totalRecords": 300,
                "hasNextPage": n < 3,
                "nextPageToken": "t{}".format(n),
                "domains": [{"domainName": "typo-{}.com".format(n)}],
            }
        )
    if path == "/v1/domain/security":
        return FakeResponse(
            body={
                "risk_category": {"verdict": "malicious"},
                "trust_signals": {"trust_score": 12},
                "intelligence": {
                    "related_iocs": [
                        {"type": "ipv4", "value": "203.0.113.9"},
                        {"type": "ipv4", "value": "45.33.32.156"},
                        {"type": "domain", "value": "evil-cdn.net"},
                    ]
                },
            }
        )
    if path == "/v1.0/ssl/live":
        return FakeResponse(
            body={
                "sslCertificates": [
                    {
                        "chainOrder": "end-user",
                        "validityEndDate": "2025-01-01 00:00:00",
                        "issuer": {"organization": "Let's Encrypt"},
                        "extensions": {
                            "subjectAlternativeNames": {
                                "dnsNames": ["www.example.com", "*.example.com"]
                            }
                        },
                    }
                ]
            }
        )
    if path == "/v1.0/subdomains":
        return FakeResponse(
            body={
                "total_records": 1500,
                "total_pages": 2,
                "subdomains": [{"subdomain": "s{}.example.com".format(page)}],
            }
        )
    if path == "/v1.0/geolocation":
        def geo(ip):
            return {
                "ip": ip,
                "location": {"city": "Mountain View", "country_code2": "US"},
                "network": {"asn": {"as_number": "AS15169"}},
            }

        if call["method"] == "GET":
            return FakeResponse(body=geo(q["ip"]))
        return FakeResponse(body=[geo(ip) for ip in body["ips"]])
    if path == "/v2.0/security":
        return FakeResponse(body=security_v2(q["ip"]))
    if path == "/v1.0/security":
        return FakeResponse(
            body=[
                security_v2(ip) if ip != "1.1.1.1" else {"ip": ip, "message": "Invalid IP"}
                for ip in body["ips"]
            ]
        )
    if path == "/v1.0/ip-whois":
        return FakeResponse(
            body={
                "organization": {"name": "Google LLC"},
                "inet_nums": [{"cidr": ["8.8.8.0/24"]}],
                "abuse_contacts": [{"email": ["network-abuse@google.com"]}],
            }
        )
    if path == "/v2.0/asn-whois":
        return FakeResponse(body={"asNumber": "15169", "asName": "GOOGLE", "country": "US"})
    return FakeResponse(404, {"status": 404, "message": "No such route"})


class FakeSession(object):
    """Stands for requests.Session: answers from queued responses, then from default_api."""

    queued = []  # [path, response or exception, remaining uses]
    calls = []
    latency = 0  # seconds a request takes on the fake clock

    def __init__(self):
        self.headers = {}

    def request(self, method, url, params=None, json=None, timeout=None, allow_redirects=True):
        parsed = urlparse(url)
        call = {
            "method": method,
            "host": parsed.netloc,
            "path": parsed.path,
            "params": params,
            "body": json,
            "timeout": timeout,
            "allow_redirects": allow_redirects,
            "headers": dict(self.headers),
        }
        FakeSession.calls.append(call)
        if timeout is not None and FakeSession.latency > timeout:
            Clock.now += timeout
            raise requests.exceptions.ReadTimeout("no answer within {} s".format(timeout))
        Clock.now += FakeSession.latency
        for entry in FakeSession.queued:
            if entry[0] == call["path"] and entry[2] > 0:
                entry[2] -= 1
                if isinstance(entry[1], Exception):
                    raise entry[1]
                return entry[1]
        return default_api(call)


class Clock(object):
    now = 1000.0
    sleeps = []

    @staticmethod
    def monotonic():
        return Clock.now

    @staticmethod
    def sleep(seconds):
        Clock.sleeps.append(seconds)
        Clock.now += seconds


def flavor_config(flavor):
    with open(os.path.join(ANALYZER, "WhoisFreaks_{}.json".format(flavor))) as f:
        definition = json.load(f)
    config = dict(definition["config"])
    for item in definition["configurationItems"]:
        if "defaultValue" in item:
            config[item["name"]] = item["defaultValue"]
    return config


def never_connected():
    reason = NewConnectionError(None, "Connection refused")
    return requests.exceptions.ConnectionError(MaxRetryError(None, "/", reason))


class AnalyzerTest(unittest.TestCase):
    def setUp(self):
        FakeSession.queued, FakeSession.calls, FakeSession.latency = [], [], 0
        Clock.now, Clock.sleeps = 1000.0, []
        self.patches = [
            mock.patch.object(whoisfreaks_api.requests, "Session", FakeSession),
            mock.patch.object(whoisfreaks_api.time, "sleep", Clock.sleep),
            mock.patch.object(whoisfreaks_api.time, "monotonic", Clock.monotonic),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def queue(self, path, response, times=1):
        FakeSession.queued.append([path, response, times])

    def run_job(
        self, flavor, data_type, data=None, file_bytes=None, config=None, params=None, tlp=2, pap=2
    ):
        cfg = flavor_config(flavor)
        cfg.update({"key": KEY, "auto_extract_artifacts": True, "jobTimeout": 30})
        cfg.update(config or {})
        job = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(job, "input"))
            data_input = {
                "dataType": data_type,
                "tlp": tlp,
                "pap": pap,
                "config": cfg,
                "parameters": params or {},
            }
            if data_type == "file":
                with open(os.path.join(job, "input", "attachment"), "wb") as f:
                    f.write(file_bytes)
                data_input.update({"file": "attachment", "filename": "iocs.txt"})
            else:
                data_input["data"] = data
            with open(os.path.join(job, "input", "input.json"), "w") as f:
                json.dump(data_input, f)
            with mock.patch.object(sys, "argv", ["whoisfreaks.py", job]):
                try:
                    whoisfreaks.WhoisFreaksAnalyzer().run()
                except SystemExit:
                    pass
            path = os.path.join(job, "output", "output.json")
            self.assertTrue(os.path.exists(path), "the job wrote no output.json")
            with open(path) as f:
                return json.load(f)
        finally:
            shutil.rmtree(job)

    @staticmethod
    def tags(output):
        return {
            t["predicate"]: (t["level"], t["value"])
            for t in output.get("summary", {}).get("taxonomies", [])
        }

    @staticmethod
    def artifacts(output):
        return [(a["dataType"], a["data"]) for a in output.get("artifacts", [])]

    def assertError(self, output, text):
        self.assertFalse(output["success"], output)
        self.assertIn(text, output["errorMessage"])
        self.assertNotIn(KEY, json.dumps(output))


class TestFlavors(AnalyzerTest):
    IOCS = (
        b"whoisfreaks.com\nhxxps://www[.]example[.]com/path\n8.8.8.8, 1.1.1.1; 185.220.101.1\n"
        b"10.0.0.1\nfoo@bar.com\nwhoisfreaks.com\n"
    )
    CASES = [
        ("Whois", "domain", "example.com", "/v2.0/whois/live", "Registrar"),
        ("Whois", "fqdn", "www.example.com", "/v2.0/whois/live", "Created"),
        ("WhoisHistory", "domain", "example.com", "/v2.0/whois/history", "WhoisHistory"),
        ("ReverseWhois", "mail", "admin@example.com", "/v2.0/whois/reverse", "ReverseWhois"),
        ("ReverseWhois", "other", "acme", "/v2.0/whois/reverse", "ReverseWhois"),
        ("DNS", "domain", "example.com", "/v2.0/dns/live", "DNS"),
        ("DNS", "ip", "8.8.8.8", "/v2.0/dns/live", "DNS"),
        ("DNSHistory", "domain", "example.com", "/v2.0/dns/historical", "DNSHistory"),
        ("ReverseDNS", "ip", "8.8.8.8", "/v2.1/dns/reverse", "ReverseDNS"),
        ("ReverseDNS", "other", "8.8.8.0/24", "/v2.1/dns/reverse", "ReverseDNS"),
        ("ReverseNS", "fqdn", "ns1.example-dns.net", "/v2.1/dns/reverse", "ReverseNS"),
        ("ReverseMX", "fqdn", "mx.example-mail.net", "/v2.1/dns/reverse", "ReverseMX"),
        ("ReverseCNAME", "fqdn", "cdn.example.net", "/v2.1/dns/reverse", "ReverseCNAME"),
        ("ReverseTXT", "other", "google-site-verification=*", "/v2.1/dns/reverse", "ReverseTXT"),
        ("DomainReputation", "domain", "bad.example.com", "/v1/domain/security", "Verdict"),
        ("DomainAvailability", "domain", "example.com", "/v2.0/domain/availability", "Available"),
        ("TLDAvailability", "domain", "paypal.com", "/v2.0/domain/availability", "Unavailable"),
        ("SSL", "domain", "example.com", "/v1.0/ssl/live", "Expired"),
        ("Subdomains", "domain", "example.com", "/v1.0/subdomains", "Subdomains"),
        ("Typosquatting", "domain", "paypal.com", "/v3.0/domain/typos", "Typosquats"),
        ("IPWhois", "ip", "8.8.8.8", "/v1.0/ip-whois", "Org"),
        ("IPReputation", "ip", "185.220.101.1", "/v2.0/security", "ThreatScore"),
        ("IPGeolocation", "ip", "8.8.8.8", "/v1.0/geolocation", "Location"),
        ("ASNWhois", "autonomous-system", "as15169", "/v2.0/asn-whois", "ASN"),
        ("BulkWhois", "file", None, "/v2.0/bulkwhois/live", "BulkWhois"),
        ("BulkDNS", "file", None, "/v2.0/dns/bulk/live", "BulkDNS"),
        ("BulkDomainAvailability", "file", None, "/v2.0/domain/availability", "Unavailable"),
        ("BulkIPGeolocation", "file", None, "/v1.0/geolocation", "BulkGeolocation"),
        ("BulkIPReputation", "file", None, "/v1.0/security", "Malicious"),
    ]

    def test_every_flavor(self):
        for flavor, data_type, data, path, predicate in self.CASES:
            with self.subTest(flavor=flavor, data_type=data_type):
                self.setUp()
                output = self.run_job(
                    flavor, data_type, data, self.IOCS if data_type == "file" else None
                )
                self.assertTrue(output["success"], output)
                self.assertEqual(FakeSession.calls[0]["path"], path)
                self.assertIn(predicate, self.tags(output))
                for call in FakeSession.calls:
                    self.assertEqual(call["host"], "api.whoisfreaks.com")
                    self.assertEqual(call["headers"]["X-API-KEY"], KEY)
                    self.assertFalse(call["allow_redirects"])
                    self.assertNotIn(KEY, json.dumps(call["params"]))
                self.tearDown()

    def test_whois_artifacts_skip_redacted_emails(self):
        output = self.run_job("Whois", "domain", "example.com")
        self.assertEqual(
            self.artifacts(output),
            [
                ("fqdn", "ns1.example-dns.net"),
                ("fqdn", "ns2.example-dns.net"),
                ("mail", "tech@example.com"),
            ],
        )

    def test_bulk_classification(self):
        output = self.run_job("BulkWhois", "file", file_bytes=self.IOCS)
        result = output["full"]["result"]
        self.assertEqual(
            FakeSession.calls[0]["body"], {"domainNames": ["whoisfreaks.com", "www.example.com"]}
        )
        reasons = {s["value"]: s["reason"] for s in result["skipped"]}
        self.assertEqual(reasons["10.0.0.1"], "private or reserved IP")
        self.assertEqual(reasons["foo@bar.com"], "email address")
        self.assertEqual(reasons["8.8.8.8"], "not a domain")

    def test_bulk_batches_of_100(self):
        names = "\n".join("dom{}.com".format(i) for i in range(250)).encode()
        output = self.run_job("BulkWhois", "file", file_bytes=names, config={"max_items": 1000})
        self.assertEqual([len(c["body"]["domainNames"]) for c in FakeSession.calls], [100, 100, 50])
        self.assertEqual(output["full"]["result"]["requests"], 3)


class TestSecurity(AnalyzerTest):
    def test_redirect_is_not_followed(self):
        self.queue(
            "/v2.0/whois/live",
            FakeResponse(302, raw="", headers={"Location": "http://collector.evil/steal"}),
        )
        output = self.run_job("Whois", "domain", "example.com")
        self.assertError(output, "Unexpected redirect from the WhoisFreaks API (HTTP 302)")
        self.assertEqual(len(FakeSession.calls), 1)

    def test_api_key_echo_removed_at_any_depth(self):
        self.queue(
            "/v1.0/geolocation",
            FakeResponse(
                body=[
                    {
                        "ip": "8.8.8.8",
                        "location": {"city": "x"},
                        "apiKey": KEY,
                        "note": "key " + KEY,
                    }
                ]
            ),
        )
        output = self.run_job("BulkIPGeolocation", "file", file_bytes=b"8.8.8.8")
        self.assertTrue(output["success"])
        self.assertNotIn(KEY, json.dumps(output))

    def test_api_key_removed_from_error_messages(self):
        self.queue("/v2.0/whois/live", FakeResponse(401, {"message": "Invalid key " + KEY}))
        output = self.run_job("Whois", "domain", "example.com")
        self.assertError(output, "Invalid key REMOVED")

    def test_failed_job_masks_the_key(self):
        self.queue(
            "/v2.0/whois/live", FakeResponse(401, {"message": "Provided API key is invalid."})
        )
        output = self.run_job("Whois", "domain", "example.com")
        self.assertEqual(output["input"]["config"]["key"], "REMOVED")

    def test_private_and_reserved_ips_are_never_sent(self):
        for ip in (
            "10.0.0.1",
            "127.0.0.1",
            "::ffff:10.0.0.1",
            "100.64.0.1",
            "fe80::1",
            "224.0.0.1",
            "192.0.2.1",
            "::1",
            "2001:db8::1",
            "0.0.0.0",
            "999.1.1.1",
        ):
            with self.subTest(ip=ip):
                FakeSession.calls = []
                output = self.run_job("IPReputation", "ip", ip)
                self.assertError(output, "is not a public IP address")
                self.assertEqual(FakeSession.calls, [])

    def test_private_cidr_is_never_sent(self):
        output = self.run_job("ReverseDNS", "other", "10.0.0.0/8")
        self.assertError(output, "is not a public IP range")
        self.assertEqual(FakeSession.calls, [])

    def test_tlp_and_pap_red_are_refused(self):
        self.assertError(self.run_job("Whois", "domain", "example.com", tlp=3), "TLP is higher")
        self.assertError(self.run_job("Whois", "domain", "example.com", pap=3), "PAP is higher")
        self.assertEqual(FakeSession.calls, [])

    def test_per_run_parameters_cannot_change_key_or_service(self):
        output = self.run_job(
            "Whois", "domain", "example.com", params={"key": "other", "service": "reverse_whois"}
        )
        self.assertTrue(output["success"])
        self.assertEqual(FakeSession.calls[0]["path"], "/v2.0/whois/live")
        self.assertEqual(FakeSession.calls[0]["headers"]["X-API-KEY"], KEY)


class TestRetries(AnalyzerTest):
    def test_get_retried_after_503(self):
        self.queue("/v2.0/whois/live", FakeResponse(503, raw="busy"))
        output = self.run_job("Whois", "domain", "example.com")
        self.assertTrue(output["success"])
        self.assertEqual(len(FakeSession.calls), 2)
        self.assertEqual(Clock.sleeps, [1])

    def test_get_gives_up_after_four_attempts(self):
        self.queue("/v2.0/whois/live", FakeResponse(500, {"message": "Internal"}), times=9)
        output = self.run_job("Whois", "domain", "example.com")
        self.assertError(output, "WhoisFreaks API returned HTTP 500: Internal")
        self.assertEqual(len(FakeSession.calls), 4)
        self.assertEqual(Clock.sleeps, [1, 2, 4])

    def test_rate_limit_header_in_nanoseconds(self):
        self.queue(
            "/v2.0/whois/live",
            FakeResponse(
                429, {"message": "slow down"}, headers={"X-RateLimit-Remaining-Time": "2000000000"}
            ),
        )
        self.assertTrue(self.run_job("Whois", "domain", "example.com")["success"])
        self.assertEqual(Clock.sleeps, [2])

    def test_retry_after_is_capped(self):
        self.queue("/v2.0/whois/live", FakeResponse(429, {}, headers={"Retry-After": "600"}))
        self.run_job("Whois", "domain", "example.com")
        self.assertEqual(Clock.sleeps, [60])

    def test_get_retried_after_dropped_connection(self):
        self.queue("/v2.0/whois/live", requests.exceptions.ConnectionError("reset"), times=2)
        self.assertTrue(self.run_job("Whois", "domain", "example.com")["success"])
        self.assertEqual(len(FakeSession.calls), 3)

    def test_slow_answer_retried_once(self):
        self.queue("/v2.1/dns/reverse", requests.exceptions.ReadTimeout("slow"))
        self.assertTrue(self.run_job("ReverseCNAME", "fqdn", "ghs.googlehosted.com")["success"])
        self.assertEqual(len(FakeSession.calls), 2)
        self.assertEqual(FakeSession.calls[0]["timeout"], whoisfreaks_api.TIMEOUT)

    def test_slow_answer_twice_is_reported_as_slow(self):
        self.queue("/v2.1/dns/reverse", requests.exceptions.ReadTimeout("slow"), times=9)
        output = self.run_job("ReverseCNAME", "fqdn", "ghs.googlehosted.com")
        self.assertError(output, "did not answer within 180 seconds (2 attempts)")
        self.assertEqual(len(FakeSession.calls), 2)

    def test_connect_timeout_gets_every_retry(self):
        self.queue("/v2.0/whois/live", requests.exceptions.ConnectTimeout("no route"), times=9)
        output = self.run_job("Whois", "domain", "example.com")
        self.assertError(output, "Unable to reach the WhoisFreaks API: ConnectTimeout")
        self.assertEqual(len(FakeSession.calls), 4)

    def test_bulk_post_not_resent_after_read_timeout(self):
        self.queue("/v2.0/bulkwhois/live", requests.exceptions.ReadTimeout("slow"))
        output = self.run_job("BulkWhois", "file", file_bytes=b"a1.com\na2.com")
        self.assertError(output, "the request was not resent")
        self.assertEqual(len(FakeSession.calls), 1)

    def test_bulk_post_not_resent_after_5xx(self):
        self.queue("/v1.0/security", FakeResponse(503, raw="busy"), times=3)
        output = self.run_job("BulkIPReputation", "file", file_bytes=b"8.8.8.8")
        self.assertError(output, "HTTP 503")
        self.assertEqual(len(FakeSession.calls), 1)

    def test_bulk_post_resent_after_429(self):
        self.queue("/v1.0/security", FakeResponse(429, {}, headers={"Retry-After": "1"}))
        self.assertTrue(self.run_job("BulkIPReputation", "file", file_bytes=b"8.8.8.8")["success"])
        self.assertEqual(len(FakeSession.calls), 2)

    def test_bulk_post_resent_when_never_connected(self):
        self.queue("/v1.0/security", never_connected())
        self.assertTrue(self.run_job("BulkIPReputation", "file", file_bytes=b"8.8.8.8")["success"])
        self.assertEqual(len(FakeSession.calls), 2)

    def test_tld_sweep_post_not_resent(self):
        self.queue("/v2.0/domain/availability", requests.exceptions.ReadTimeout("slow"))
        output = self.run_job("TLDAvailability", "other", "acme")
        self.assertError(output, "not resent")
        self.assertEqual(len(FakeSession.calls), 1)

    def test_deadline_stops_paging_and_keeps_pages(self):
        # A 1-minute job keeps 6 s free; each page takes 20 s
        FakeSession.latency = 20
        output = self.run_job(
            "ReverseWhois", "other", "acme", config={"max_pages": 3, "jobTimeout": 1}
        )
        self.assertTrue(output["success"])
        result = output["full"]["result"]
        self.assertEqual(result["pages_fetched"], 2)
        self.assertIn("time limit", result["error"])
        self.assertEqual(self.tags(output)["Incomplete"], ("info", "yes"))

    def test_request_timeout_shortened_before_deadline(self):
        FakeSession.latency = 40
        self.run_job("ReverseWhois", "other", "acme", config={"max_pages": 2, "jobTimeout": 1})
        self.assertEqual(FakeSession.calls[0]["timeout"], 54)
        self.assertEqual(FakeSession.calls[1]["timeout"], 14)

    def test_later_page_error_keeps_earlier_pages(self):
        self.queue(
            "/v2.1/dns/reverse",
            FakeResponse(
                200,
                {
                    "totalRecords": 9,
                    "totalPages": 3,
                    "reverseDnsRecords": [{"domainName": "p1.com"}],
                },
            ),
        )
        self.queue("/v2.1/dns/reverse", FakeResponse(413, {"message": "Credit limit reached"}))
        output = self.run_job("ReverseDNS", "ip", "8.8.8.8", config={"max_pages": 3})
        self.assertTrue(output["success"])
        self.assertIn("Stopped after page 1", output["full"]["result"]["error"])
        self.assertEqual(self.artifacts(output), [("fqdn", "p1.com")])

    def test_later_bulk_batch_error_keeps_results(self):
        names = "\n".join("dom{}.com".format(i) for i in range(150)).encode()
        self.queue(
            "/v2.0/bulkwhois/live",
            FakeResponse(
                200,
                {"bulk_whois_response": [whois_record("dom{}.com".format(i)) for i in range(100)]},
            ),
        )
        self.queue("/v2.0/bulkwhois/live", FakeResponse(413, {"message": "Credit limit reached"}))
        output = self.run_job("BulkWhois", "file", file_bytes=names, config={"max_items": 1000})
        self.assertTrue(output["success"])
        self.assertIn("Stopped after 100 of 150", output["full"]["result"]["error"])
        self.assertEqual(self.tags(output)["Incomplete"], ("info", "yes"))


class TestErrors(AnalyzerTest):
    def expect(
        self,
        status,
        body,
        text,
        flavor="Whois",
        data="example.com",
        path="/v2.0/whois/live",
        data_type="domain",
    ):
        self.queue(path, FakeResponse(status, body))
        self.assertError(self.run_job(flavor, data_type, data), text)

    def test_invalid_key(self):
        self.expect(
            401,
            {"message": "Provided API key is invalid."},
            "WhoisFreaks rejected the API key (HTTP 401)",
        )

    def test_no_credits(self):
        self.expect(
            401,
            {"message": "You have no API credits left. Please buy credits"},
            "plan or credit problem (HTTP 401)",
        )

    def test_documented_inactive_tld(self):
        self.expect(
            403,
            {
                "message": "Provided domain belongs to an inactive TLD. Please try to use "
                "historical whois lookup."
            },
            "Domain extension not supported or inactive at WhoisFreaks (HTTP 403)",
        )

    def test_unsupported_extension(self):
        self.expect(403, {"message": "Not supported domain extension"}, "not supported or inactive")

    def test_403_key_denied(self):
        self.expect(403, {"message": "Unauthorized"}, "rejected the API key (HTTP 403)")

    def test_403_other(self):
        self.expect(403, {"message": "Forbidden"}, "WhoisFreaks refused this lookup (HTTP 403)")

    def test_plan_and_credit_limits(self):
        self.expect(
            412, {"message": "Plan limit reached"}, "plan or quota limit reached (HTTP 412)"
        )
        self.expect(
            413, {"message": "Credit limit reached"}, "plan or quota limit reached (HTTP 413)"
        )

    def test_bogon_ip(self):
        self.expect(
            423,
            {"message": "bogon"},
            "private, reserved or bogon IP addresses (HTTP 423)",
            "IPGeolocation",
            "8.8.8.8",
            "/v1.0/geolocation",
            "ip",
        )

    def test_rate_limit_persists(self):
        self.queue("/v2.0/whois/live", FakeResponse(429, {"message": "Too many"}), times=9)
        self.assertError(
            self.run_job("Whois", "domain", "example.com"),
            "WhoisFreaks rate limit exceeded: Too many",
        )

    def test_not_found_is_a_successful_job(self):
        self.queue("/v2.0/whois/live", FakeResponse(404, {"message": "No Record Found"}))
        output = self.run_job("Whois", "domain", "example.com")
        self.assertTrue(output["success"])
        self.assertEqual(self.tags(output)["Result"], ("info", "not found"))

    def test_status_false_no_record(self):
        self.queue(
            "/v2.0/whois/live", FakeResponse(200, {"status": False, "message": "No Record Found"})
        )
        self.assertFalse(self.run_job("Whois", "domain", "example.com")["full"]["found"])

    def test_non_json_and_empty_bodies(self):
        for raw in ("{not json", ""):
            with self.subTest(raw=raw):
                self.queue("/v2.0/whois/live", FakeResponse(200, raw=raw))
                self.assertError(
                    self.run_job("Whois", "domain", "example.com"), "non-JSON response"
                )

    def test_network_failure(self):
        self.queue("/v2.0/whois/live", requests.exceptions.ConnectionError("down"), times=9)
        self.assertError(
            self.run_job("Whois", "domain", "example.com"),
            "Unable to reach the WhoisFreaks API: ConnectionError",
        )

    def test_unsupported_data_type(self):
        self.assertError(self.run_job("Whois", "ip", "8.8.8.8"), "not supported")


class TestMalformedResponses(AnalyzerTest):
    """Responses outside the documented schema end in a message or a report, never a traceback."""

    def test_page_is_a_list(self):
        self.queue("/v2.0/whois/reverse", FakeResponse(200, []))
        self.assertError(self.run_job("ReverseWhois", "other", "acme"), "unexpected response")

    def test_contact_is_a_string(self):
        self.queue(
            "/v2.0/whois/live",
            FakeResponse(200, {"domain_name": "example.com", "registrant_contact": "REDACTED"}),
        )
        self.assertTrue(self.run_job("Whois", "domain", "example.com")["success"])

    def test_as_number_is_an_integer(self):
        self.queue(
            "/v2.0/security",
            FakeResponse(200, {"security": {"threat_score": 3}, "asn": {"as_number": 15169}}),
        )
        output = self.run_job("IPReputation", "ip", "8.8.8.8")
        self.assertIn(("autonomous-system", "AS15169"), self.artifacts(output))

    def test_null_dns_record(self):
        self.queue(
            "/v2.0/dns/live",
            FakeResponse(200, {"dnsRecords": [None, {"dnsType": "A", "address": "8.8.4.4"}]}),
        )
        output = self.run_job("DNS", "domain", "example.com")
        self.assertEqual(self.artifacts(output), [("ip", "8.8.4.4")])

    def test_security_block_is_a_string(self):
        self.queue("/v2.0/security", FakeResponse(200, {"security": "unavailable"}))
        output = self.run_job("IPReputation", "ip", "8.8.8.8")
        self.assertEqual(self.tags(output)["ThreatScore"], ("info", "unknown"))

    def test_organization_is_a_list(self):
        self.queue(
            "/v1.0/ip-whois",
            FakeResponse(
                200, {"organization": [{"name": "X"}], "inet_nums": [{"cidr": ["8.8.8.0/24"]}]}
            ),
        )
        output = self.run_job("IPWhois", "ip", "8.8.8.8")
        self.assertEqual(self.tags(output)["Network"], ("info", "8.8.8.0/24"))

    def test_bulk_body_of_the_wrong_type(self):
        self.queue("/v1.0/geolocation", FakeResponse(200, {"results": []}))
        self.assertError(
            self.run_job("BulkIPGeolocation", "file", file_bytes=b"8.8.8.8"),
            "unexpected bulk response",
        )

    def test_bulk_answers_fewer_items(self):
        self.queue(
            "/v2.0/bulkwhois/live",
            FakeResponse(200, {"bulk_whois_response": [whois_record("a1.com")]}),
        )
        output = self.run_job("BulkWhois", "file", file_bytes=b"a1.com\na2.com\na3.com")
        self.assertEqual(output["full"]["result"]["missing"], 2)
        self.assertEqual(self.tags(output)["Missing"], ("info", 2))


class TestData(AnalyzerTest):
    def ip_reputation(self, security, config=None):
        self.queue("/v2.0/security", FakeResponse(200, {"security": security}))
        return self.tags(self.run_job("IPReputation", "ip", "8.8.8.8", config=config))

    def test_known_good_bot_is_not_suspicious(self):
        tags = self.ip_reputation({"threat_score": 0, "is_bot": True, "is_known_good_bot": True})
        self.assertEqual(tags["ThreatScore"], ("safe", 0))
        self.assertNotIn("Flags", tags)
        self.assertEqual(tags["Context"], ("info", "Known good bot"))

    def test_relay_is_context_only(self):
        tags = self.ip_reputation({"threat_score": 10, "is_relay": True})
        self.assertNotIn("Flags", tags)
        self.assertEqual(tags["Context"], ("info", "Relay"))

    def test_unknown_signals_are_not_safe(self):
        self.assertEqual(
            self.ip_reputation({"threat_score": None}), {"ThreatScore": ("info", "unknown")}
        )

    def test_configurable_thresholds(self):
        tags = self.ip_reputation(
            {"threat_score": 50}, {"ip_suspicious_score": 60, "ip_malicious_score": 90}
        )
        self.assertEqual(tags["ThreatScore"], ("safe", 50))

    def test_thresholds_validated(self):
        output = self.run_job(
            "IPReputation",
            "ip",
            "8.8.8.8",
            config={"ip_suspicious_score": 80, "ip_malicious_score": 70},
        )
        self.assertError(output, "ip_suspicious_score must not be higher")
        self.assertEqual(FakeSession.calls, [])

    def test_bulk_unknown_verdict(self):
        self.queue("/v1.0/security", FakeResponse(200, [{"ip": "8.8.8.8", "security": {}}]))
        output = self.run_job("BulkIPReputation", "file", file_bytes=b"8.8.8.8")
        self.assertEqual(self.tags(output)["Unknown"], ("info", 1))
        self.assertEqual(output["artifacts"][0]["tags"][-1], "unknown")

    def test_partial_and_cached_records_flagged(self):
        for status, predicate in ((206, "Partial"), (210, "Cached")):
            with self.subTest(status=status):
                self.queue("/v2.0/whois/live", FakeResponse(status, whois_record("example.com")))
                output = self.run_job("Whois", "domain", "example.com")
                self.assertEqual(self.tags(output)[predicate], ("info", "yes"))

    def test_bulk_dns_ip_entry_stays_an_ip(self):
        output = self.run_job("BulkDNS", "file", file_bytes=b"8.8.8.8")
        self.assertEqual(self.artifacts(output), [("ip", "8.8.8.8")])

    def test_observables_capped(self):
        self.queue(
            "/v1.0/subdomains",
            FakeResponse(
                200,
                {
                    "total_pages": 1,
                    "subdomains": [{"subdomain": "s{}.example.com".format(i)} for i in range(1500)],
                },
            ),
        )
        output = self.run_job("Subdomains", "domain", "example.com")
        self.assertEqual(len(output["artifacts"]), whoisfreaks.MAX_ARTIFACTS)
        self.assertEqual(output["full"]["artifacts_truncated"], 1500)
        self.assertIn("Observables", self.tags(output))

    def test_domain_reputation_drops_non_public_iocs(self):
        output = self.run_job("DomainReputation", "domain", "bad.example.com")
        self.assertEqual(
            self.artifacts(output), [("ip", "45.33.32.156"), ("domain", "evil-cdn.net")]
        )


class TestInput(AnalyzerTest):
    def test_international_domain_sent_as_punycode(self):
        self.run_job("Whois", "domain", "Bücher.de")
        self.assertEqual(FakeSession.calls[0]["params"]["domainName"], "xn--bcher-kva.de")

    def test_malformed_domain_rejected(self):
        output = self.run_job("Whois", "domain", "a.b/c?d=e&domainName=evil.com")
        self.assertError(output, "Invalid domain")
        self.assertEqual(FakeSession.calls, [])

    def test_ipv4_mapped_address_sent_as_ipv4(self):
        self.run_job("IPGeolocation", "ip", "::ffff:8.8.8.8")
        self.assertEqual(FakeSession.calls[0]["params"]["ip"], "8.8.8.8")

    def test_cidr_reverse_dns(self):
        output = self.run_job("ReverseDNS", "other", "8.8.8.1/24")
        self.assertEqual(FakeSession.calls[0]["params"]["value"], "8.8.8.0/24")
        self.assertEqual(FakeSession.calls[0]["params"]["type"], "a")
        self.assertEqual(output["full"]["observable"], "8.8.8.0/24")

    def test_asn_formats(self):
        for value in ("AS15169", "as15169", "15169"):
            with self.subTest(value=value):
                FakeSession.calls = []
                self.run_job("ASNWhois", "autonomous-system", value)
                self.assertEqual(FakeSession.calls[0]["params"]["asn"], "AS15169")

    def file_entries(self, raw):
        self.run_job("BulkDNS", "file", file_bytes=raw)
        body = FakeSession.calls[0]["body"]
        return body.get("domainNames", []) + body.get("ipAddresses", [])

    def test_utf8_bom(self):
        self.assertEqual(
            self.file_entries(b"\xef\xbb\xbfwhoisfreaks.com\nexample.org\n"),
            ["whoisfreaks.com", "example.org"],
        )

    def test_utf16_file(self):
        self.assertEqual(
            self.file_entries("whoisfreaks.com\r\nexample.org\r\n".encode("utf-16")),
            ["whoisfreaks.com", "example.org"],
        )

    def test_url_forms(self):
        raw = (
            "http://[2606:4700:4700::1111]:8080/x\nhttps://user:pw@evil.example.com:8443/a?b#c\n"
            "1.2.3.4:443\nhxxp://bad[.]example[.]net\nbücher.de\nEXAMPLE.ORG."
        ).encode()
        self.assertEqual(
            sorted(self.file_entries(raw)),
            sorted(
                [
                    "2606:4700:4700::1111",
                    "evil.example.com",
                    "1.2.3.4",
                    "bad.example.net",
                    "xn--bcher-kva.de",
                    "example.org",
                ]
            ),
        )

    def test_no_deprecation_warning(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            self.file_entries(b"https://example.com/a/b?c")

    def test_file_limits(self):
        self.assertError(self.run_job("BulkWhois", "file", file_bytes=b""), "holds no domain names")
        self.assertError(
            self.run_job("BulkWhois", "file", file_bytes=b"x" * 1000001),
            "larger than 1000000 bytes",
        )


class TestOptions(AnalyzerTest):
    def test_invalid_credit_limits_stop_the_job(self):
        for value in (0, "abc", 50, 2.5, "inf"):
            with self.subTest(value=value):
                output = self.run_job("ReverseWhois", "other", "acme", config={"max_pages": value})
                self.assertError(output, "max_pages must be a whole number from 1 to 20")

    def test_run_can_lower_but_not_raise_limits(self):
        self.run_job(
            "ReverseWhois", "other", "acme", config={"max_pages": 2}, params={"max_pages": 5}
        )
        self.assertEqual(len(FakeSession.calls), 2)
        FakeSession.calls = []
        self.run_job(
            "ReverseWhois", "other", "acme", config={"max_pages": 3}, params={"max_pages": 1}
        )
        self.assertEqual(len(FakeSession.calls), 1)

    def test_infinite_page_size_is_a_clean_error(self):
        output = self.run_job(
            "Typosquatting", "domain", "paypal.com", params={"typosquatting_page_size": "inf"}
        )
        self.assertError(output, "typosquatting_page_size must be a whole number from 1 to 100")

    def test_option_validation_before_any_request(self):
        cases = [
            ("DNS", "domain", "example.com", {"dns_record_types": "A,XYZ"}, "dns_record_types"),
            ("DNS", "domain", "example.com", {"dns_cname_depth": 9}, "dns_cname_depth"),
            (
                "DNS",
                "domain",
                "example.com",
                {"dns_relative_records": "maybe"},
                "dns_relative_records",
            ),
            (
                "ReverseWhois",
                "other",
                "acme",
                {"reverse_whois_search_type": "x"},
                "reverse_whois_search_type",
            ),
            (
                "TLDAvailability",
                "other",
                "acme",
                {"availability_tlds": "com,bad_tld!"},
                "availability_tlds",
            ),
            (
                "Subdomains",
                "domain",
                "example.com",
                {"subdomains_after": "01/02/2025"},
                "subdomains_after",
            ),
            ("Typosquatting", "other", "*p*a*y*", {}, "at most 3 wildcards"),
        ]
        for flavor, data_type, data, config, text in cases:
            with self.subTest(flavor=flavor, text=text):
                FakeSession.calls = []
                self.assertError(self.run_job(flavor, data_type, data, config=config), text)
                self.assertEqual(FakeSession.calls, [])

    def test_bulk_dns_adds_ptr_for_ips(self):
        self.run_job(
            "BulkDNS", "file", file_bytes=b"example.com\n8.8.8.8", config={"dns_record_types": "A"}
        )
        self.assertEqual(FakeSession.calls[0]["params"]["type"], "A,PTR")


if __name__ == "__main__":
    unittest.main()
