#!/usr/bin/env python3
# encoding: utf-8

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import re

import requests
from cortexutils.analyzer import Analyzer

API_URL = "https://sochain.com/api/v3"
HTTP_TIMEOUT = 15
ROWS = 25
NETWORKS = ("BTC", "LTC", "DOGE", "ZEC")
# Tried first when the address starts like this; every network is still tried in the end.
PREFIXES = {
    "BTC": ("bc1", "1", "3"),
    "LTC": ("ltc1", "L", "M", "3"),
    "DOGE": ("D", "A", "9"),
    "ZEC": ("t1", "t3"),
}
ADDRESS_RE = re.compile(r"^[A-Za-z0-9]{1,1000}$")


class SoChainError(Exception):
    pass


class SoChain(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.key = self.get_param("config.key", None)

    def _get(self, endpoint, network, address, **params):
        """The data of an answer, or None when SoChain answers 404."""
        headers = {"Accept": "application/json"}
        if self.key:
            headers["API-KEY"] = self.key
        try:
            response = requests.get(
                "{}/{}/{}/{}".format(API_URL, endpoint, network, address),
                headers=headers,
                params=params,
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException as e:
            raise SoChainError("Not able to reach SoChain: {}".format(e))
        if response.status_code == 404:
            return None
        if response.status_code == 401:
            raise SoChainError("SoChain refused the API key. Check it at https://sochain.com/dashboard.")
        if response.status_code == 429:
            raise SoChainError(
                "SoChain's lookup limit is reached. An API key from https://sochain.com/dashboard raises it."
            )
        try:
            payload = response.json()
        except ValueError:
            raise SoChainError("SoChain answered with HTTP {} and no JSON.".format(response.status_code))
        if response.status_code != 200 or payload.get("status") != "success":
            message = (payload.get("data") or {}).get("error_message") or "HTTP {}".format(response.status_code)
            raise SoChainError("SoChain: {}".format(message))
        return payload["data"]

    def _network(self, address):
        if self.data_type == "btc_address":
            return "BTC"
        hinted = [n for n in NETWORKS if address.startswith(PREFIXES[n])]
        for network in hinted + [n for n in NETWORKS if n not in hinted]:
            data = self._get("is_valid_address", network, address)
            if data and data.get("is_valid"):
                return network
        return None

    @staticmethod
    def _coin(amount):
        try:
            return Decimal(amount)
        except (InvalidOperation, TypeError):
            raise SoChainError("SoChain returned an amount that is not a number: {!r}".format(amount))

    @staticmethod
    def _block(block):
        if not block:
            return None
        return {
            "height": block.get("height"),
            "time": datetime.fromtimestamp(int(block["time"]), tz=timezone.utc).isoformat(),
        }

    def lookup(self, address):
        network = self._network(address)
        if network is None:
            raise SoChainError("{} is not a BTC, LTC, DOGE or ZEC address.".format(address))
        summary = self._get("address_summary", network, address)
        if summary is None:
            raise SoChainError("{} is not a valid {} address.".format(address, network))
        counterparties = self._get("address_counterparties", network, address, limit=ROWS) or {}
        # None: SoChain has no poisoning check for this network.
        poisoning = self._get("address_poisoning", network, address, limit=ROWS)

        balance = self._coin(summary["confirmed_balance"])
        received = self._coin(summary["confirmed_received"])
        findings = (poisoning or {}).get("findings") or []
        return {
            "address": address,
            "network": network,
            "balance": format(balance, "f"),
            "unconfirmed_balance": format(self._coin(summary.get("unconfirmed_balance") or "0"), "f"),
            "total_received": format(received, "f"),
            # Confirmed received minus confirmed balance.
            "total_sent": format(received - balance, "f"),
            "txs_total": summary.get("txs_total"),
            "txs_received": summary.get("txs_received"),
            "txs_sent": summary.get("txs_sent"),
            "first_active": self._block(summary.get("first_active")),
            "last_active": self._block(summary.get("last_active")),
            "poisoning": {
                "checked": poisoning is not None,
                "targeted": bool(findings),
                "lookalikes": sorted({f["sender"] for f in findings if f.get("sender")}),
                "building": bool((poisoning or {}).get("building")),
                "findings": findings,
            },
            "counterparties": {
                "window_blocks": counterparties.get("window_blocks"),
                "from_height": counterparties.get("from_height"),
                "building": bool(counterparties.get("building")),
                "rows": counterparties.get("counterparties") or [],
            },
            "explorer": "https://sochain.com/{}/address/{}".format(network.lower(), address),
        }

    def summary(self, raw):
        taxonomies = [
            self.build_taxonomy("info", "SoChain", "Network", raw["network"]),
            self.build_taxonomy("info", "SoChain", "Balance", "{} {}".format(raw["balance"], raw["network"])),
            self.build_taxonomy("info", "SoChain", "Transactions", str(raw["txs_total"])),
        ]
        lookalikes = raw["poisoning"]["lookalikes"]
        if lookalikes:
            taxonomies.append(
                self.build_taxonomy("suspicious", "SoChain", "Poisoning", "{} look-alike(s)".format(len(lookalikes)))
            )
        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        seen = set()
        for lookalike in raw["poisoning"]["lookalikes"]:
            seen.add(lookalike)
            artifacts.append(
                self.build_artifact(
                    self.data_type,
                    lookalike,
                    tags=["sochain:address-poisoning", "network:{}".format(raw["network"])],
                    message="Look-alike address that sent {} dust".format(raw["address"]),
                )
            )
        for row in raw["counterparties"]["rows"]:
            address = row.get("address")
            if not address or address in seen or address == raw["address"]:
                continue
            seen.add(address)
            artifacts.append(
                self.build_artifact(
                    self.data_type,
                    address,
                    tags=["sochain:counterparty", "network:{}".format(raw["network"])],
                )
            )
        return artifacts

    def run(self):
        Analyzer.run(self)
        address = (self.get_data() or "").strip()
        if not ADDRESS_RE.match(address):
            self.error("{} is not a cryptocurrency address.".format(address))
        try:
            report = self.lookup(address)
        except SoChainError as e:
            self.error(str(e))
        self.report(report)


if __name__ == "__main__":
    SoChain().run()
