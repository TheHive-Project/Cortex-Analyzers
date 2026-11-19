#!/usr/bin/env python3
# encoding: utf-8
"""Minimal WhoisFreaks lookup API client used by the WhoisFreaks analyzer.

Each method returns the parsed JSON body of one API call. Errors are raised as
WhoisFreaksError (or one of its subclasses) with a message safe to show in
TheHive: the API key travels in the X-API-KEY header and never appears in a
URL, a message or a returned body.
"""

import ipaddress
import time

import requests
from urllib3.exceptions import NewConnectionError

API_HOST = "https://api.whoisfreaks.com"
USER_AGENT = "cortex-whoisfreaks-analyzer/1.0"
# Lookups with millions of results (reverse DNS on a large host) can take minutes to answer
TIMEOUT = 180
MAX_RETRIES = 3
# A lookup still unanswered after TIMEOUT is resent once: resending it more only adds load
SLOW_ANSWER_RETRIES = 1
RETRY_AFTER_CAP = 60
MIN_REQUEST_TIME = 5  # seconds left before the deadline below which no request is started
RETRYABLE_STATUS = (408, 429, 500, 502, 503, 504)
# The server bills a bulk POST once it has read it, so a POST is only resent when it surely
# was not processed: rate-limited, or never connected
POST_RETRYABLE_STATUS = (429,)
SECRET_FIELDS = ("apikey", "api_key")
MIN_SECRET_LENGTH = 8  # shorter keys are not searched for in text, to avoid mangling data

QUOTA_KEYWORDS = (
    "quota", "credits", "subscription", "download limit", "please buy",
    "upgrade your plan", "add api credits", "plan does not have",
)
UNSUPPORTED_TLD_KEYWORDS = (
    "not supported domain extension", "not providing the whois of this domain",
    "unsupported tld", "unsupported extension", "inactive tld", "domain extension",
)
NOT_FOUND_KEYWORDS = ("not found", "no record", "does not exist")
AUTH_KEYWORDS = ("invalid api", "invalid key", "unauthorized", "api key is invalid")

REVERSE_WHOIS_TYPES = ("keyword", "email", "owner", "company")
BULK_LIMIT = 100  # items per bulk request


class WhoisFreaksError(Exception):
    """Any failure talking to the WhoisFreaks API."""


class NotFoundError(WhoisFreaksError):
    """The API holds no record for the queried value."""


class DeadlineError(WhoisFreaksError):
    """Too little of the job's time is left to send another request."""


def _error_detail(response):
    try:
        body = response.json()
    except ValueError:
        return response.text.strip()[:200]
    if isinstance(body, dict):
        for key in ("message", "msg", "error", "detail", "description"):
            if isinstance(body.get(key), str) and body[key].strip():
                return body[key].strip()
    return ""


def _flag(value):
    return "true" if value else "false"


def _never_sent(error):
    """True when a request failed before a connection was made, so resending it is safe."""
    if isinstance(error, requests.exceptions.ConnectTimeout):
        return True
    reason = getattr(error.args[0], "reason", None) if error.args else None
    return isinstance(reason, NewConnectionError)


def redact(value, secret):
    """Copy of a parsed body without echoed API keys, at any depth, nor the key's text."""
    if isinstance(value, dict):
        return {k: redact(v, secret) for k, v in value.items()
                if str(k).lower() not in SECRET_FIELDS}
    if isinstance(value, list):
        return [redact(v, secret) for v in value]
    if isinstance(value, str) and secret and len(secret) >= MIN_SECRET_LENGTH and secret in value:
        return value.replace(secret, "REMOVED")
    return value


def is_public_ip(value):
    """True only for a globally routable IPv4/IPv6 address."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return addr.is_global and not addr.is_multicast


class WhoisFreaksApi(object):

    def __init__(self, api_key, session=None, deadline=None):
        self.api_key = api_key
        # time.monotonic() value after which no request starts (Cortex kills the job at its timeout)
        self.deadline = deadline
        # 2xx codes other than 200 received: 206 (partial record) and 210 (cached record)
        self.statuses = set()
        self.session = session or requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            "X-API-KEY": api_key,
        })

    # -- transport ---------------------------------------------------------

    @staticmethod
    def _retry_after(response):
        raw = response.headers.get("Retry-After")
        if raw and raw.isdigit():
            return min(int(raw), RETRY_AFTER_CAP)
        # WhoisFreaks rate-limit header: remaining window in nanoseconds
        raw = response.headers.get("x-ratelimit-remaining-time")
        if raw and raw.isdigit():
            return min(max(1, int(raw) // 1000000000), RETRY_AFTER_CAP)
        return None

    def _remaining(self):
        return None if self.deadline is None else self.deadline - time.monotonic()

    def _timeout(self):
        """Read timeout of the next request, shortened so it ends before the deadline."""
        remaining = self._remaining()
        if remaining is None:
            return TIMEOUT
        if remaining < MIN_REQUEST_TIME:
            raise DeadlineError("The job's time limit is reached; no further WhoisFreaks request "
                                "was sent")
        return min(TIMEOUT, remaining)

    def _sleep(self, seconds):
        remaining = self._remaining()
        if remaining is not None and remaining - seconds < MIN_REQUEST_TIME:
            raise DeadlineError("The job's time limit is reached while waiting to retry the "
                                "WhoisFreaks API")
        time.sleep(seconds)

    def _get(self, version, path, params):
        return self._request("GET", version, path, params)

    def _post(self, version, path, body, params=None):
        return self._request("POST", version, path, params, body)

    def _request(self, method, version, path, params, body=None):
        url = "{}/{}/{}".format(API_HOST, version, path)
        retryable = RETRYABLE_STATUS if method == "GET" else POST_RETRYABLE_STATUS
        slow_answers = 0
        for attempt in range(MAX_RETRIES + 1):
            timeout = self._timeout()
            try:
                # The API never redirects: following one would send the key to another host
                response = self.session.request(method, url, params=params, json=body,
                                                timeout=timeout, allow_redirects=False)
            except requests.exceptions.RequestException as e:
                if method != "GET" and not _never_sent(e):
                    raise WhoisFreaksError(
                        "No answer from the WhoisFreaks API ({}); the request was not resent "
                        "because it may already have been processed and billed".format(
                            e.__class__.__name__)) from None
                if isinstance(e, requests.exceptions.ReadTimeout):
                    slow_answers += 1
                    if slow_answers > SLOW_ANSWER_RETRIES:
                        raise WhoisFreaksError(
                            "The WhoisFreaks API did not answer within {} seconds ({} attempts); "
                            "lookups with millions of results can be slow, try again later".format(
                                int(timeout), slow_answers)) from None
                if attempt >= MAX_RETRIES:
                    raise WhoisFreaksError("Unable to reach the WhoisFreaks API: {}".format(
                        e.__class__.__name__)) from None
                self._sleep(2 ** attempt)
                continue

            status = response.status_code
            if status in retryable and attempt < MAX_RETRIES:
                self._sleep(self._retry_after(response) or 2 ** attempt)
                continue
            if 200 <= status < 300:
                if status != 200:
                    self.statuses.add(status)
                return self._parse(response)
            if 300 <= status < 400:
                raise WhoisFreaksError("Unexpected redirect from the WhoisFreaks API (HTTP {}); "
                                       "it was not followed".format(status))
            self._raise_for_status(response)
        raise WhoisFreaksError("WhoisFreaks API request failed after {} attempts".format(
            MAX_RETRIES + 1))

    def _raise_for_status(self, response):
        status = response.status_code
        detail = redact(_error_detail(response), self.api_key)
        lowered = detail.lower()
        suffix = ": {}".format(detail) if detail else ""
        if status in (401, 403) and any(k in lowered for k in QUOTA_KEYWORDS):
            raise WhoisFreaksError("WhoisFreaks plan or credit problem (HTTP {}){}".format(
                status, suffix))
        if status == 401 or (status == 403 and any(k in lowered for k in AUTH_KEYWORDS)):
            raise WhoisFreaksError("WhoisFreaks rejected the API key (HTTP {}){}".format(
                status, suffix))
        if status == 403:
            # Documented as an unsupported or inactive TLD; the message says which
            if any(k in lowered for k in UNSUPPORTED_TLD_KEYWORDS):
                raise WhoisFreaksError(
                    "Domain extension not supported or inactive at WhoisFreaks (HTTP 403){}"
                    .format(suffix))
            raise WhoisFreaksError("WhoisFreaks refused this lookup (HTTP 403){}".format(suffix))
        if status == 404:
            raise NotFoundError(detail or "Record not found")
        if status in (400, 422):
            raise WhoisFreaksError("WhoisFreaks rejected the request (HTTP {}){}".format(
                status, suffix))
        if status in (412, 413):
            raise WhoisFreaksError("WhoisFreaks plan or quota limit reached (HTTP {}){}".format(
                status, suffix))
        if status == 423:
            raise WhoisFreaksError("WhoisFreaks does not look up private, reserved or bogon IP "
                                   "addresses (HTTP 423){}".format(suffix))
        if status == 429:
            raise WhoisFreaksError("WhoisFreaks rate limit exceeded{}".format(suffix))
        raise WhoisFreaksError("WhoisFreaks API returned HTTP {}{}".format(status, suffix))

    def _parse(self, response):
        try:
            data = response.json()
        except ValueError:
            raise WhoisFreaksError("WhoisFreaks API returned a non-JSON response (HTTP {})".format(
                response.status_code)) from None
        data = redact(data, self.api_key)
        # Some endpoints report failures as {"status": false, ...} with HTTP 200
        if isinstance(data, dict) and data.get("status") in (False, "error", "failed"):
            message = str(data.get("error") or data.get("message") or data.get("msg")
                          or "API returned status=false")
            lowered = message.lower()
            if any(k in lowered for k in NOT_FOUND_KEYWORDS):
                raise NotFoundError(message)
            if any(k in lowered for k in AUTH_KEYWORDS):
                raise WhoisFreaksError("WhoisFreaks rejected the API key: {}".format(message))
            raise WhoisFreaksError("WhoisFreaks API error: {}".format(message))
        return data

    # -- WHOIS -------------------------------------------------------------

    def live_whois(self, domain):
        return self._get("v2.0", "whois/live", {"domainName": domain})

    def historical_whois(self, domain):
        return self._get("v2.0", "whois/history", {"domainName": domain})

    def reverse_whois(self, query, search_type, exact=False, page=1, mode="default"):
        return self._get("v2.0", "whois/reverse", {
            search_type: query,
            "mode": mode,
            "exact": _flag(exact),
            "page": page,
        })

    def bulk_whois(self, domains):
        return self._post("v2.0", "bulkwhois/live", {"domainNames": domains})

    # -- DNS ---------------------------------------------------------------

    def live_dns(self, value, is_ip=False, record_types="all", cname_depth=None,
                 relative_records=True):
        params = {"type": record_types}
        params["ipAddress" if is_ip else "domainName"] = value
        if cname_depth is not None:
            params["cnameDepth"] = cname_depth
        if not relative_records:
            params["relativeRecords"] = "false"
        return self._get("v2.0", "dns/live", params)

    def historical_dns(self, domain, page=1, record_types="all"):
        return self._get("v2.0", "dns/historical", {
            "domainName": domain, "type": record_types, "page": page})

    def reverse_dns(self, value, record_type, page=1, exact=True, sort=None):
        params = {"value": value, "type": record_type, "exact": _flag(exact), "page": page}
        if sort:
            params["sort"] = sort
        return self._get("v2.1", "dns/reverse", params)

    def bulk_dns(self, domains=None, ips=None, record_types="all", cname_depth=None):
        body = {}
        if domains:
            body["domainNames"] = domains
        if ips:
            body["ipAddresses"] = ips
        params = {"type": record_types}
        if cname_depth is not None:
            params["cname_depth"] = cname_depth
        return self._post("v2.0", "dns/bulk/live", body, params)

    # -- Domain ------------------------------------------------------------

    def domain_availability(self, domain, suggestions=0):
        params = {"domain": domain, "sug": "false"}
        if suggestions:
            params.update({"sug": "true", "count": suggestions})
        return self._get("v2.0", "domain/availability", params)

    def bulk_domain_availability(self, domains):
        return self._post("v2.0", "domain/availability", {"domainNames": domains})

    def tld_availability(self, label, tlds):
        # The bulk endpoint's second form: one label checked across a list of TLDs
        return self._post("v2.0", "domain/availability", {"tld": tlds}, {"domain": label})

    def domain_reputation(self, domain):
        return self._get("v1", "domain/security", {"domainName": domain})

    def typosquatting(self, keyword=None, pattern=None, page_token=None, page_size=None):
        # The API ignores a page number: later pages need the previous page's nextPageToken
        params = {"keyword": keyword} if keyword else {"pattern": pattern}
        if page_token:
            params["pageToken"] = page_token
        if page_size:
            params["fetch_size"] = page_size
        return self._get("v3.0", "domain/typos", params)

    def ssl_lookup(self, domain, chain=False):
        return self._get("v1.0", "ssl/live", {
            "domainName": domain, "chain": _flag(chain), "sslRaw": "false"})

    def subdomains(self, domain, page=1, status=None, after=None, before=None):
        params = {"domain": domain, "page": page}
        for name, value in (("status", status), ("after", after), ("before", before)):
            if value:
                params[name] = value
        return self._get("v1.0", "subdomains", params)

    # -- IP / ASN ----------------------------------------------------------

    def ip_whois(self, ip):
        return self._get("v1.0", "ip-whois", {"ip": ip})

    def ip_security(self, ip):
        return self._get("v2.0", "security", {"ip": ip})

    def bulk_ip_security(self, ips):
        # Bulk stays on v1.0: the documented POST /v2.0/security returns 404
        return self._post("v1.0", "security", {"ips": ips})

    def ip_geolocation(self, ip):
        return self._get("v1.0", "geolocation", {"ip": ip})

    def bulk_ip_geolocation(self, ips):
        return self._post("v1.0", "geolocation", {"ips": ips})

    def asn_whois(self, asn):
        return self._get("v2.0", "asn-whois", {"asn": asn})
