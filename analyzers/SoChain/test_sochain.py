#!/usr/bin/env python3
"""
Unittests for the SoChain analyzer. HTTP is mocked: no network calls.
"""
import io
import json
import os
import sys
import unittest
from unittest import mock

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import SoChain as sochain  # noqa: E402

BTC = "bc1qxhmdufsvnuaaaer4ynz88fspdsxq2h9e9cetdj"
PAID = "36bLmGg2pQ71rSZyxaUGmk8ggu6Lp5VPPz"
PAYER = "bc1q368c8ue4p3c6pty3k0m7zu6jndspx23x3a78r9r9jyekffeqhdlqkd5dl0"
LOOKALIKE = "36bLmGg2pQ71rSZyxaUGmk8ggu6Lp5VPZz"
DOGE = "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"

# Shaped as SoChain answered on 23 Oct 2026, cut to a few rows.
SUMMARY = {
    "txs_sent": 1796,
    "txs_received": 32014,
    "txs_total": 32014,
    "confirmed_balance": "0.12771030",
    "unconfirmed_balance": "0.00000000",
    "confirmed_received": "285785.38685032",
    "first_active": {"height": 687848, "time": 1623874601},
    "last_active": {"height": 972455, "time": 1792576976},
}
COUNTERPARTIES = {
    "address": BTC,
    "window_blocks": 4320,
    "from_height": 968436,
    "building": False,
    "counterparties": [
        {"address": PAID, "direction": "sent", "amount": "0.01017653", "txid": "95" * 32, "height": 972455},
        {"address": PAYER, "direction": "received", "amount": "0.01017653", "txid": "0b" * 32, "height": 972446},
        {"address": PAID, "direction": "sent", "amount": "0.01069309", "txid": "cd" * 32, "height": 971974},
    ],
}
POISONING = {
    "address": BTC,
    "building": False,
    "findings": [
        {
            "dust_txid": "dd" * 32,
            "amount": "0.00000546",
            "sender": LOOKALIKE,
            "imitates": PAID,
            "real_txid": "95" * 32,
            "real_height": 972455,
            "real_amount": "0.01017653",
            "receiver_paid": False,
            "shared_prefix": 4,
            "shared_suffix": 4,
            "sender_kind": "new",
            "sender_txs": 1,
            "height": 972460,
            "confirmed": True,
        }
    ],
}


class MockResponse:
    def __init__(self, data=None, status_code=200, payload=None):
        self.status_code = status_code
        self.payload = payload if payload is not None else {"status": "success", "data": data}

    def json(self):
        return self.payload


def fail(status_code):
    return MockResponse(status_code=status_code, payload={"status": "fail", "data": {"error_message": "x"}})


class TestSoChain(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.answers = {
            "address_summary": MockResponse(SUMMARY),
            "address_counterparties": MockResponse(COUNTERPARTIES),
            "address_poisoning": MockResponse(POISONING),
        }
        self.valid_on = ("BTC",)
        self.stdout = sys.stdout

    def tearDown(self):
        sys.stdout = self.stdout
        sys.stdin = sys.__stdin__

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append((url, headers, params))
        endpoint, network = url.split("/api/v3/")[1].split("/")[:2]
        if endpoint == "is_valid_address":
            return MockResponse({"is_valid": network in self.valid_on})
        return self.answers[endpoint]

    def run_analyzer(self, data, data_type="crypto_address", key=None):
        config = {"check_tlp": True, "max_tlp": 2}
        if key:
            config["key"] = key
        job = {"data": data, "dataType": data_type, "tlp": 0, "config": config}
        sys.stdin = io.StringIO(json.dumps(job))
        sys.stdout = io.StringIO()
        with mock.patch.object(sochain.requests, "get", side_effect=self.get):
            try:
                sochain.SoChain().run()
            except SystemExit:
                pass
        output = sys.stdout.getvalue()
        sys.stdout = self.stdout
        return json.loads(output)

    def test_report(self):
        result = self.run_analyzer(BTC, data_type="btc_address")
        self.assertTrue(result["success"])
        full = result["full"]
        self.assertEqual(full["network"], "BTC")
        self.assertEqual(full["balance"], "0.12771030")
        self.assertEqual(full["total_received"], "285785.38685032")
        # received minus balance, exactly
        self.assertEqual(full["total_sent"], "285785.25914002")
        self.assertEqual(full["unconfirmed_balance"], "0.00000000")
        self.assertEqual(full["txs_total"], 32014)
        self.assertEqual(full["first_active"], {"height": 687848, "time": "2021-06-16T20:16:41+00:00"})
        self.assertEqual(full["explorer"], "https://sochain.com/btc/address/" + BTC)
        self.assertEqual(len(full["counterparties"]["rows"]), 3)

    def test_btc_address_skips_network_detection(self):
        self.run_analyzer(BTC, data_type="btc_address")
        self.assertFalse(any("is_valid_address" in url for url, _, _ in self.calls))

    def test_crypto_address_detects_the_network(self):
        self.valid_on = ("DOGE",)
        result = self.run_analyzer(DOGE)
        self.assertEqual(result["full"]["network"], "DOGE")
        tried = [url.split("/")[-2] for url, _, _ in self.calls if "is_valid_address" in url]
        # a D address is tried on Dogecoin first
        self.assertEqual(tried, ["DOGE"])
        self.assertTrue(all("/DOGE/" in url for url, _, _ in self.calls))

    def test_address_valid_nowhere(self):
        self.valid_on = ()
        result = self.run_analyzer("Xnotanaddress")
        self.assertFalse(result["success"])
        self.assertIn("not a BTC, LTC, DOGE or ZEC address", result["errorMessage"])
        self.assertEqual(len(self.calls), len(sochain.NETWORKS))

    def test_poisoning_taxonomy_and_artifacts(self):
        result = self.run_analyzer(BTC, data_type="btc_address")
        taxonomies = {t["predicate"]: t for t in result["summary"]["taxonomies"]}
        self.assertEqual(taxonomies["Poisoning"]["level"], "suspicious")
        self.assertEqual(taxonomies["Poisoning"]["value"], "1 look-alike(s)")
        self.assertEqual(taxonomies["Balance"]["value"], "0.12771030 BTC")
        artifacts = {a["data"]: a for a in result["artifacts"]}
        # the look-alike, then each counterparty once
        self.assertEqual(set(artifacts), {LOOKALIKE, PAID, PAYER})
        self.assertIn("sochain:address-poisoning", artifacts[LOOKALIKE]["tags"])
        self.assertIn("sochain:counterparty", artifacts[PAID]["tags"])
        self.assertTrue(all(a["dataType"] == "btc_address" for a in result["artifacts"]))

    def test_no_poisoning_no_taxonomy(self):
        self.answers["address_poisoning"] = MockResponse({"address": BTC, "building": False, "findings": []})
        result = self.run_analyzer(BTC)
        predicates = [t["predicate"] for t in result["summary"]["taxonomies"]]
        self.assertEqual(predicates, ["Network", "Balance", "Transactions"])
        self.assertTrue(result["full"]["poisoning"]["checked"])
        self.assertFalse(result["full"]["poisoning"]["targeted"])

    def test_network_without_poisoning_check(self):
        self.answers["address_poisoning"] = fail(404)
        result = self.run_analyzer(BTC)
        self.assertTrue(result["success"])
        self.assertFalse(result["full"]["poisoning"]["checked"])

    def test_unknown_address(self):
        self.answers["address_summary"] = fail(404)
        result = self.run_analyzer(BTC, data_type="btc_address")
        self.assertFalse(result["success"])

    def test_api_key_header(self):
        self.run_analyzer(BTC, data_type="btc_address")
        self.assertTrue(all("API-KEY" not in headers for _, headers, _ in self.calls))
        self.calls = []
        self.run_analyzer(BTC, data_type="btc_address", key="my-key")
        self.assertTrue(all(headers["API-KEY"] == "my-key" for _, headers, _ in self.calls))

    def test_bad_key_and_rate_limit_name_the_dashboard(self):
        for status in (401, 429):
            self.answers["address_summary"] = fail(status)
            result = self.run_analyzer(BTC, data_type="btc_address")
            self.assertFalse(result["success"])
            self.assertIn("https://sochain.com/dashboard", result["errorMessage"])

    def test_unreachable(self):
        sys.stdin = io.StringIO(json.dumps({"data": BTC, "dataType": "btc_address", "tlp": 0, "config": {}}))
        sys.stdout = io.StringIO()
        with mock.patch.object(sochain.requests, "get", side_effect=requests.ConnectionError("down")):
            with self.assertRaises(SystemExit):
                sochain.SoChain().run()
        result = json.loads(sys.stdout.getvalue())
        self.assertTrue(result["errorMessage"].startswith("Not able to reach SoChain"))

    def test_not_an_address(self):
        result = self.run_analyzer("not an address")
        self.assertFalse(result["success"])
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
