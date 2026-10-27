#!/usr/bin/env python3
# encoding: utf-8

import ipaddress
from urllib.parse import urlparse

import requests
from cortexutils.analyzer import Analyzer

USER_AGENT = "netapi-cortex/1.0 (+https://github.com/TheHive-Project/Cortex-Analyzers)"
API_URL = "https://netapi.com/api-json/"


class NetAPIAnalyzer(Analyzer):
    """Check a domain or URL against the NetAPI compromised feed and the NetAPI Top 1M.

    Two free JSON methods, no account needed:
    - compromised-check: is the value, or the registered domain it belongs to, in the feed of
      hosts that public threat feeds report for malware or phishing, now (seen in the last 24 h)
      or in the past, with first / last seen, the reporting feed and the registrar;
    - domain-rank: the domain's position in the NetAPI Top 1M, rebuilt daily.

    An optional NetAPI API token only raises the rate limits.
    """

    def __init__(self):
        Analyzer.__init__(self)
        self.timeout = int(self.get_param("config.timeout", 30))
        token = self.get_param("config.key", None)

        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        if token:
            self.session.headers["Authorization"] = "Bearer {}".format(token)

    # --- HTTP ---------------------------------------------------------------

    def _get(self, method, **params):
        """GET one JSON API method. Errors come back as {"error": {"code", "message"}}."""
        params["method"] = method
        try:
            response = self.session.get(API_URL, params=params, timeout=self.timeout)
        except requests.RequestException as error:
            self.error("NetAPI request failed: {}".format(error))

        try:
            body = response.json()
        except ValueError:
            self.error(
                "NetAPI returned HTTP {} with a non-JSON body for {}".format(
                    response.status_code, method
                )
            )
        if response.status_code >= 400:
            message = (body.get("error") or {}).get("message") or "HTTP {}".format(
                response.status_code
            )
            self.error("NetAPI {}: {}".format(method, message))
        return body

    def _value(self):
        """The host to look up: a URL is checked by its host name."""
        data = str(self.get_data()).strip()
        if self.data_type == "url":
            host = urlparse(data if "://" in data else "http://" + data).hostname
            if not host:
                self.error("Could not extract a host from URL {}".format(data))
            try:
                ipaddress.ip_address(host)
            except ValueError:
                return host
            self.error("URL host {} is an IP address, not a domain name".format(host))
        return data

    # --- Cortex -------------------------------------------------------------

    def run(self):
        if self.data_type not in ("domain", "fqdn", "url"):
            self.notSupported()

        value = self._value()
        check = self._get("compromised-check", value=value)
        # download links of the feed, not part of the answer about this observable
        check.pop("lists", None)
        report = {"observable": value, "compromised": check}

        # popularity helps triage a listing: a top-ranked domain in the feed is more likely a
        # compromised legitimate site than infrastructure set up by the attacker
        if check.get("type") == "domain":
            rank = self._get("domain-rank", domain=value)
            rank.pop("links", None)
            report["rank"] = rank

        self.report(report)

    def summary(self, raw):
        taxonomies = []
        namespace = "NetAPI"

        check = raw.get("compromised") or {}
        matched = check.get("matched_value")
        via = ""
        if matched and matched != raw.get("observable"):
            # the listing belongs to the registered domain, not to this exact host
            via = " via {}".format(matched)
        if check.get("listed_now"):
            taxonomies.append(
                self.build_taxonomy(
                    "malicious", namespace, "Compromised", "listed now{}".format(via)
                )
            )
        elif check.get("listed_ever"):
            # An old listing is mostly a past incident, often a compromised legitimate host
            # that was cleaned up since: context, not a verdict.
            last_seen = str(check.get("last_seen") or "")[:10]
            taxonomies.append(
                self.build_taxonomy(
                    "info",
                    namespace,
                    "Compromised",
                    "listed until {}{}".format(last_seen, via),
                )
            )
        else:
            # Deliberately "info" and never "safe": absence from the feed is not a clearance.
            taxonomies.append(
                self.build_taxonomy("info", namespace, "Compromised", "not listed")
            )

        rank = raw.get("rank")
        if rank is not None:
            value = (
                "#{}".format(rank["rank"]) if rank.get("in_top_1m") else "not ranked"
            )
            taxonomies.append(self.build_taxonomy("info", namespace, "Top1M", value))

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        # the report only links NetAPI pages (registrar page), which are no observables
        return []


if __name__ == "__main__":
    NetAPIAnalyzer().run()
