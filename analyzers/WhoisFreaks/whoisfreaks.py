#!/usr/bin/env python3
# encoding: utf-8

import ipaddress
import re
import time
from collections import Counter
from datetime import date, datetime

from cortexutils.analyzer import Analyzer
from whoisfreaks_api import (
    BULK_LIMIT,
    REVERSE_WHOIS_TYPES,
    NotFoundError,
    WhoisFreaksApi,
    WhoisFreaksError,
    is_public_ip,
)

NAMESPACE = "WhoisFreaks"
NEW_DOMAIN_DAYS = 30
MAX_PAGES_LIMIT = 20
MAX_ITEMS_DEFAULT = 100
MAX_ITEMS_LIMIT = 1000
MAX_FILE_BYTES = 1000000
MAX_ARTIFACTS = 1000  # suggested observables per job; a bulk run never needs more
SKIPPED_SHOWN = 100
JOB_TIMEOUT_DEFAULT = 30  # minutes, Cortex's default job timeout
DEADLINE_MARGIN = 60  # seconds kept free before the job timeout to write the report
IP_MALICIOUS_SCORE = 75
IP_SUSPICIOUS_SCORE = 40
ASN_RE = re.compile(r"^(?:as)?(\d{1,10})$", re.IGNORECASE)
KEYWORD_RE = re.compile(r"^[a-z0-9-]{3,63}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.IGNORECASE)
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9_-]{1,63}\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
TLD_RE = re.compile(r"^[a-z0-9-]{2,63}(?:\.[a-z0-9-]{2,63})?$")
DEFAULT_TLDS = "com,net,org,info,biz,io,co,xyz"
MAX_TLDS = 100
DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SPF", "TXT")
# reverse DNS service on a host name or text -> (record type searched, summary predicate)
REVERSE_RECORD_SERVICES = {
    "reverse_ns": ("ns", "ReverseNS"),
    "reverse_mx": ("mx", "ReverseMX"),
    "reverse_cname": ("cname", "ReverseCNAME"),
    "reverse_txt": ("txt", "ReverseTXT"),
}
TOKEN_SPLIT_RE = re.compile(r"[\s,;|]+")
DEFANG_DOT_RE = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE)
# bulk service -> (entries it accepts, list key of the response; None for a bare list)
BULK_SERVICES = {
    "bulk_whois": ("domain", "bulk_whois_response"),
    "bulk_dns": ("any", "bulk_dns_info"),
    "bulk_domain_availability": ("domain", "bulk_domain_availability_response"),
    "bulk_ip_geolocation": ("ip", None),
    "bulk_ip_reputation": ("ip", None),
}
CONTACTS = ("registrant_contact", "administrative_contact", "technical_contact", "billing_contact")
# Risk flags: any of them makes an IP suspicious, a known attacker malicious
IP_FLAGS = (
    ("is_known_attacker", "Known attacker"),
    ("is_tor", "Tor"),
    ("is_vpn", "VPN"),
    ("is_proxy", "Proxy"),
    ("is_residential_proxy", "Residential proxy"),
    ("is_bot", "Bot"),
    ("is_spam", "Spam"),
)
# Shown for context only: privacy relays carry ordinary users' traffic, and a known good bot is a
# declared crawler or monitor (search engines...)
IP_CONTEXT_FLAGS = (("is_relay", "Relay"), ("is_known_good_bot", "Known good bot"))
VERDICT_LEVELS = {
    "malicious": "malicious",
    "suspicious": "suspicious",
    "safe": "safe",
    "clean": "safe",
    "benign": "safe",
}


def _int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _dict(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def _dicts(value):
    """The objects of a JSON array; anything else in it, or a non-array, is ignored."""
    return [item for item in _list(value) if isinstance(item, dict)]


def _count(number, noun):
    return "{} {}{}".format(number, noun, "" if number == 1 else "s")


def _host(value):
    """Normalise a DNS name; None for empty, wildcard or malformed values."""
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip(".").lower()
    if not value or "*" in value or " " in value or "." not in value:
        return None
    return value


def _domain(value):
    """A host name in lower-case ASCII (IDNA for international names); None when malformed."""
    host = _host(value)
    if not host:
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return host if DOMAIN_RE.match(host) else None


def _ip(value):
    """Canonical text of an IP address, an IPv4-mapped IPv6 one as IPv4; None if not an IP."""
    if not isinstance(value, str):
        return None
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return str(getattr(addr, "ipv4_mapped", None) or addr)


def _parse_date(value):
    """Date part of 'YYYY-MM-DD[ ...]' strings returned by the API."""
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def _created(record):
    """Creation date of a WHOIS record; the registry copy holds it when the registrar's lacks it."""
    return _parse_date(record.get("create_date")
                       or _dict(record.get("registry_data")).get("create_date"))


def _ip_flags(security):
    """Labels of the risk flags set on an IP. A declared good bot does not count as a bot."""
    good_bot = security.get("is_known_good_bot") is True
    return [label for key, label in IP_FLAGS
            if security.get(key) is True and not (key == "is_bot" and good_bot)]


def _ip_verdict(security, malicious=IP_MALICIOUS_SCORE, suspicious=IP_SUSPICIOUS_SCORE):
    """Cortex level of an IP security block; info when the API gave neither score nor flag."""
    score = _int(security.get("threat_score"), None)
    if security.get("is_known_attacker") is True or (score is not None and score >= malicious):
        return "malicious"
    if (score is not None and score >= suspicious) or _ip_flags(security):
        return "suspicious"
    return "safe" if score is not None else "info"


def _classify(token):
    """Read one entry of a bulk file: ('ip' | 'domain', value), or (None, reason to skip it)."""
    token = DEFANG_DOT_RE.sub(".", token).strip("[]()<>{}\"'")
    if "://" in token:
        # A URL: keep its host, without user info or port
        token = re.split(r"[/?#]", token.split("://", 1)[1], maxsplit=1)[0].rsplit("@", 1)[-1]
        if token.startswith("["):
            token = token[1:].split("]", 1)[0]
    if "@" in token:
        return None, "email address"
    if token.count(":") == 1:
        # host:port (an IPv6 address has several colons)
        token = token.split(":")[0]
    ip = _ip(token)
    if ip is not None:
        return ("ip", ip) if is_public_ip(ip) else (None, "private or reserved IP")
    host = _domain(token)
    if host:
        return "domain", host
    return None, "not a domain or IP address"


def _bulk_ok(service, item):
    """True when a bulk result item holds data rather than a per-item error."""
    if service == "bulk_ip_geolocation":
        return isinstance(item.get("location"), dict)
    if service == "bulk_ip_reputation":
        return isinstance(item.get("security"), dict)
    return item.get("status") is True


def _bulk_value(service, item):
    if service == "bulk_whois":
        return item.get("domain_name")
    if service == "bulk_dns":
        # An IP lookup can also carry the PTR name in domainName
        return item.get("ipAddress") or item.get("domainName")
    if service == "bulk_domain_availability":
        return item.get("domain")
    return item.get("ip")


def _expect_dict(data):
    if not isinstance(data, dict):
        raise WhoisFreaksError("WhoisFreaks API returned an unexpected response (a JSON {} "
                               "instead of an object)".format(type(data).__name__))
    return data


class WhoisFreaksAnalyzer(Analyzer):

    # service -> data types it accepts
    SERVICES = {
        "whois": ("domain", "fqdn"),
        "whois_history": ("domain",),
        "reverse_whois": ("mail", "other"),
        "dns": ("domain", "fqdn", "ip"),
        "dns_history": ("domain", "fqdn"),
        # 'other' holds a CIDR range
        "reverse_dns": ("ip", "other"),
        # Name servers, mail servers and CNAME targets are host names: TheHive's fqdn type
        "reverse_ns": ("fqdn",),
        "reverse_mx": ("fqdn",),
        "reverse_cname": ("fqdn",),
        "reverse_txt": ("other",),
        "domain_reputation": ("domain", "fqdn"),
        "domain_availability": ("domain",),
        "tld_availability": ("domain", "other"),
        "ssl": ("domain", "fqdn"),
        "subdomains": ("domain",),
        "typosquatting": ("domain", "other"),
        "ip_whois": ("ip",),
        "ip_reputation": ("ip",),
        "ip_geolocation": ("ip",),
        "asn_whois": ("autonomous-system",),
        # Bulk services read a text file listing domains and/or IP addresses
        "bulk_whois": ("file",),
        "bulk_dns": ("file",),
        "bulk_domain_availability": ("file",),
        "bulk_ip_geolocation": ("file",),
        "bulk_ip_reputation": ("file",),
    }

    # IP verdict thresholds; the IP reputation services read them from the configuration
    ip_malicious = IP_MALICIOUS_SCORE
    ip_suspicious = IP_SUSPICIOUS_SCORE

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param("config.service", None, "WhoisFreaks service is missing")
        api_key = self.get_param("config.key", None, "Missing WhoisFreaks API key")
        self.max_pages = self._limit("max_pages", 1, MAX_PAGES_LIMIT)
        self.max_items = self._limit("max_items", MAX_ITEMS_DEFAULT, MAX_ITEMS_LIMIT)
        self.api = WhoisFreaksApi(api_key, deadline=self._deadline())
        self.query = {}
        self._artifacts = None

    def _deadline(self):
        """When to stop sending requests: Cortex kills a job at its timeout, losing its results."""
        minutes = _int(self.get_param("config.jobTimeout"), JOB_TIMEOUT_DEFAULT)
        budget = max(minutes, 1) * 60
        return time.monotonic() + budget - min(DEADLINE_MARGIN, budget / 10)

    # -- options -----------------------------------------------------------
    # An option is read from the job's "parameters" first (set per run through the Cortex
    # API, for example by a playbook), then from the Cortex analyzer configuration.

    def _option(self, name, default=None):
        for source in ("parameters.", "config."):
            value = self.get_param(source + name, None)
            if value is not None and value != "":
                return value
        return default

    def _whole(self, value, default, name, low, high):
        """A whole number from low to high; default when the value is unset."""
        if value is None or value == "":
            return default
        try:
            number = int(float(value))
            valid = number == float(value) and not isinstance(value, bool)
        except (TypeError, ValueError, OverflowError):
            valid = False
        if not valid or not low <= number <= high:
            self.error("{} must be a whole number from {} to {}".format(name, low, high))
        return number

    def _limit(self, name, default, upper):
        """A credit limit: the Cortex setting caps it; a per-run parameter can only lower it."""
        limit = self._whole(self.get_param("config." + name), default, name, 1, upper)
        wanted = self._whole(self.get_param("parameters." + name), limit, name, 1, upper)
        return min(wanted, limit)

    def _bool_option(self, name, default):
        value = self._option(name, default)
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ("true", "1", "yes", "on"):
            return True
        if text in ("false", "0", "no", "off"):
            return False
        self.error("{} must be true or false".format(name))

    def _int_option(self, name, default, low, high):
        return self._whole(self._option(name, default), default, name, low, high)

    def _choice_option(self, name, default, choices):
        value = str(self._option(name, default)).strip().lower()
        if value not in choices:
            self.error("{} must be one of {}".format(name, ", ".join(choices)))
        return value

    def _date_option(self, name):
        value = self._option(name)
        if value is None:
            return None
        value = str(value).strip()
        if len(value) != 10 or not _parse_date(value):
            self.error("{} must be a date written YYYY-MM-DD".format(name))
        return value

    def _dns_types(self, with_ptr=False):
        """The dns_record_types option as the API's `type` value."""
        value = str(self._option("dns_record_types", "all")).replace(" ", "").upper()
        if value == "ALL":
            return "all"
        types = [t for t in value.split(",") if t]
        if not types or any(t not in DNS_TYPES for t in types):
            self.error("dns_record_types must be all or a comma-separated list of {}".format(
                ", ".join(DNS_TYPES)))
        if with_ptr and "PTR" not in types:
            types.append("PTR")
        return ",".join(types)

    def _tlds(self):
        value = self._option("availability_tlds", DEFAULT_TLDS)
        items = value if isinstance(value, list) else TOKEN_SPLIT_RE.split(str(value))
        tlds = []
        for item in items:
            tld = str(item).strip().lower().lstrip(".")
            if not tld:
                continue
            if not TLD_RE.match(tld):
                self.error("availability_tlds holds an invalid TLD: {!r}".format(str(item)[:40]))
            if tld not in tlds:
                tlds.append(tld)
        if not 1 <= len(tlds) <= MAX_TLDS:
            self.error("availability_tlds must list 1 to {} TLDs".format(MAX_TLDS))
        return tlds

    def _ip_thresholds(self):
        """Scores from which an IP is malicious or suspicious; WhoisFreaks defines none."""
        malicious = self._int_option("ip_malicious_score", IP_MALICIOUS_SCORE, 1, 100)
        suspicious = self._int_option("ip_suspicious_score", IP_SUSPICIOUS_SCORE, 1, 100)
        if suspicious > malicious:
            self.error("ip_suspicious_score must not be higher than ip_malicious_score")
        self.ip_malicious, self.ip_suspicious = malicious, suspicious

    # -- input -------------------------------------------------------------

    def _observable(self):
        value = str(self.get_data() or "").strip()
        if not value:
            self.error("Empty observable")
        if self.data_type in ("domain", "fqdn"):
            value = _domain(value)
            if not value:
                self.error("Invalid {}: {}".format(self.data_type, self.get_data()))
        elif self.data_type == "ip":
            ip = _ip(value)
            if not ip or not is_public_ip(ip):
                self.error("{} is not a public IP address; it is not sent to WhoisFreaks"
                           .format(value))
            value = ip
        elif self.data_type == "autonomous-system":
            match = ASN_RE.match(value)
            if not match:
                self.error("Invalid autonomous system number: {}".format(value))
            value = "AS" + match.group(1)
        elif self.service == "reverse_dns":
            # An 'other' observable for reverse DNS is a CIDR range
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                network = None
            if network is None or not network.is_global or network.is_multicast:
                self.error("{} is not a public IP range (CIDR); it is not sent to WhoisFreaks"
                           .format(value))
            value = str(network)
        return value

    def _paged(self, fetch, list_key, pages_key):
        """Fetch up to max_pages pages and concatenate their list_key arrays."""
        result = _expect_dict(fetch(1))
        last_page = min(self.max_pages, _int(result.get(pages_key), 1))
        page = 1
        while page < last_page:
            try:
                next_result = _expect_dict(fetch(page + 1))
            except NotFoundError:
                break
            except WhoisFreaksError as e:
                # Keep the pages already paid for and say where it stopped
                result["error"] = "Stopped after page {}: {}".format(page, e)
                break
            page += 1
            result[list_key] = _list(result.get(list_key)) + _list(next_result.get(list_key))
        result["pages_fetched"] = page
        return result

    # -- services ----------------------------------------------------------

    def _reverse_whois(self, value):
        if self.data_type == "mail":
            search_type = "email"
        else:
            search_type = self._choice_option("reverse_whois_search_type", "keyword",
                                              REVERSE_WHOIS_TYPES)
        exact = self._bool_option("reverse_whois_exact", False)
        mode = self._choice_option("reverse_whois_mode", "default", ("default", "mini"))
        self.query = {"search_type": search_type, "exact": exact, "mode": mode}
        return self._paged(
            lambda page: self.api.reverse_whois(value, search_type, exact, page, mode),
            "whois_domains_historical", "total_Pages")

    def _reverse_dns(self, value, record_type):
        # A * in the value makes it a wildcard pattern, which needs exact=false
        exact = "*" not in value
        sort = self._choice_option("reverse_dns_sort", "none", ("none", "asc", "desc"))
        sort = None if sort == "none" else sort
        self.query = {"record_type": record_type, "exact": exact}
        if sort:
            self.query["sort"] = sort
        return self._paged(
            lambda page: self.api.reverse_dns(value, record_type, page, exact, sort),
            "reverseDnsRecords", "totalPages")

    def _tld_availability(self, value):
        label = value.split(".")[0] if self.data_type == "domain" else value.lower()
        if not LABEL_RE.match(label):
            self.error("The name to check must be one label of letters, digits or hyphens, "
                       "got {!r}".format(label[:70]))
        tlds = self._tlds()
        self.query = {"label": label, "tlds": tlds}
        return self.api.tld_availability(label, tlds)

    def _typosquatting(self, value):
        keyword = pattern = None
        if self.data_type == "domain":
            keyword = value.split(".")[0]
        elif "*" in value:
            pattern = value.lower()
            if value.count("*") > 3:
                self.error("A typosquatting pattern accepts at most 3 wildcards")
        else:
            keyword = value.lower()
        if keyword is not None and not KEYWORD_RE.match(keyword):
            self.error("Typosquatting keyword must be one label of 3-63 letters, digits "
                       "or hyphens, got {!r}".format(keyword))
        self.query = {"keyword": keyword} if keyword else {"pattern": pattern}
        page_size = self._int_option("typosquatting_page_size", None, 1, 100)
        # This endpoint pages with a token from the previous page, not with a page number
        result = _expect_dict(self.api.typosquatting(keyword, pattern, page_size=page_size))
        token = result.get("nextPageToken") if result.get("hasNextPage") else None
        page = 1
        while page < self.max_pages and token:
            try:
                next_result = _expect_dict(
                    self.api.typosquatting(keyword, pattern, token, page_size))
            except NotFoundError:
                break
            except WhoisFreaksError as e:
                result["error"] = "Stopped after page {}: {}".format(page, e)
                break
            page += 1
            result["domains"] = _list(result.get("domains")) + _list(next_result.get("domains"))
            token = next_result.get("nextPageToken") if next_result.get("hasNextPage") else None
        result.pop("nextPageToken", None)
        result["hasNextPage"] = bool(token)
        result["pages_fetched"] = page
        return result

    def _bulk_entries(self, accepts):
        """Read the observable file: the entries to look up and the ones skipped, with why."""
        path = self.get_param("file", None, "File is missing")
        try:
            with open(path, "rb") as f:
                raw = f.read(MAX_FILE_BYTES + 1)
        except (OSError, TypeError):
            self.error("Unable to read the observable file")
        if len(raw) > MAX_FILE_BYTES:
            self.error("The file is larger than {} bytes".format(MAX_FILE_BYTES))
        # UTF-8 with or without a byte order mark, or UTF-16 with one (Windows "Unicode")
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = raw.decode("utf-16", "replace")
        else:
            text = raw.decode("utf-8-sig", "replace")
        entries, skipped, seen = [], [], set()
        for line in text.splitlines():
            for token in TOKEN_SPLIT_RE.split(line.split("#", 1)[0]):
                if not token:
                    continue
                kind, value = _classify(token)
                # A repeated entry is handled once, whether it is looked up or skipped
                identity = (kind, value) if kind else (None, token.lower())
                if identity in seen:
                    continue
                seen.add(identity)
                if kind is None:
                    reason = value
                elif accepts not in ("any", kind):
                    reason = "not a domain" if accepts == "domain" else "not an IP address"
                elif len(entries) >= self.max_items:
                    reason = "over the max_items limit of {}".format(self.max_items)
                else:
                    entries.append((kind, value))
                    continue
                skipped.append({"value": token[:200], "reason": reason})
        return entries, skipped

    def _bulk(self):
        accepts, list_key = BULK_SERVICES[self.service]
        entries, skipped = self._bulk_entries(accepts)
        if not entries:
            wanted = {"domain": "domain names", "ip": "public IP addresses"}.get(
                accepts, "domain names or public IP addresses")
            self.error("The file holds no {} to look up ({} entries skipped)".format(
                wanted, len(skipped)))
        options = {}
        if self.service == "bulk_dns":
            # IPs only have PTR records: add PTR when the record types are restricted
            options = {
                "record_types": self._dns_types(with_ptr=any(k == "ip" for k, _ in entries)),
                "cname_depth": self._int_option("dns_cname_depth", None, 0, 4),
            }
            self.query = {k: v for k, v in options.items() if v is not None and v != "all"}
        results, requests_made, missing, error = [], 0, 0, None
        for start in range(0, len(entries), BULK_LIMIT):
            chunk = entries[start:start + BULK_LIMIT]
            domains = [value for kind, value in chunk if kind == "domain"]
            ips = [value for kind, value in chunk if kind == "ip"]
            try:
                response = self._bulk_call(domains, ips, options)
                items = _dict(response).get(list_key) if list_key else response
                if not isinstance(items, list):
                    raise WhoisFreaksError("WhoisFreaks API returned an unexpected bulk response")
            except WhoisFreaksError as e:
                if not results:
                    raise
                # Keep the results already paid for and say where it stopped
                error = "Stopped after {} of {} entries: {}".format(start, len(entries), e)
                break
            requests_made += 1
            batch = _dicts(items)
            # The API answers one item per entry; report the ones it left out
            missing += max(0, len(chunk) - len(batch))
            results.extend(batch)
        result = {
            "submitted": len(entries),
            "requests": requests_made,
            "results": results,
            "missing": missing,
            "skipped_count": len(skipped),
            "skipped": skipped[:SKIPPED_SHOWN],
        }
        if error:
            result["error"] = error
        return result

    def _bulk_call(self, domains, ips, options):
        api = self.api
        service = self.service
        if service == "bulk_whois":
            return api.bulk_whois(domains)
        if service == "bulk_dns":
            return api.bulk_dns(domains, ips, **options)
        if service == "bulk_domain_availability":
            return api.bulk_domain_availability(domains)
        if service == "bulk_ip_geolocation":
            return api.bulk_ip_geolocation(ips)
        return api.bulk_ip_security(ips)

    def _call(self, value):
        api = self.api
        service = self.service
        if service == "whois":
            return api.live_whois(value)
        if service == "whois_history":
            return api.historical_whois(value)
        if service == "reverse_whois":
            return self._reverse_whois(value)
        if service == "dns":
            is_ip = self.data_type == "ip"
            # An IP only has a PTR record, so its lookup always asks for every type
            record_types = "all" if is_ip else self._dns_types()
            cname_depth = self._int_option("dns_cname_depth", None, 0, 4)
            relative = self._bool_option("dns_relative_records", True)
            if record_types != "all":
                self.query["record_types"] = record_types
            if cname_depth is not None:
                self.query["cname_depth"] = cname_depth
            if not relative:
                self.query["relative_records"] = False
            return api.live_dns(value, is_ip, record_types, cname_depth, relative)
        if service == "dns_history":
            record_types = self._dns_types()
            if record_types != "all":
                self.query = {"record_types": record_types}
            return self._paged(lambda page: api.historical_dns(value, page, record_types),
                               "historicalDnsRecords", "totalPages")
        if service == "reverse_dns":
            return self._reverse_dns(value, "aaaa" if ":" in value else "a")
        if service in REVERSE_RECORD_SERVICES:
            return self._reverse_dns(value, REVERSE_RECORD_SERVICES[service][0])
        if service == "domain_reputation":
            return api.domain_reputation(value)
        if service == "domain_availability":
            suggestions = self._int_option("availability_suggestions", 0, 0, 100)
            result = _expect_dict(api.domain_availability(value, suggestions))
            if "availability" not in result:
                # With suggestions the answer is only a list, the queried domain among them
                for item in _dicts(result.get("domain_available_response")):
                    if str(item.get("domain", "")).lower() == value:
                        result.update({"domain": value, "availability": item.get("availability")})
            return result
        if service == "tld_availability":
            return self._tld_availability(value)
        if service == "ssl":
            chain = self._bool_option("ssl_chain", False)
            if chain:
                self.query = {"chain": True}
            return api.ssl_lookup(value, chain)
        if service == "subdomains":
            status = self._choice_option("subdomains_status", "all", ("all", "active", "inactive"))
            status = None if status == "all" else status
            after = self._date_option("subdomains_after")
            before = self._date_option("subdomains_before")
            self.query = {k: v for k, v in (("status", status), ("after", after),
                                            ("before", before)) if v}
            return self._paged(lambda page: api.subdomains(value, page, status, after, before),
                               "subdomains", "total_pages")
        if service == "typosquatting":
            return self._typosquatting(value)
        if service == "ip_whois":
            return api.ip_whois(value)
        if service == "ip_reputation":
            self._ip_thresholds()
            return api.ip_security(value)
        if service == "ip_geolocation":
            return api.ip_geolocation(value)
        if service in BULK_SERVICES:
            if service == "bulk_ip_reputation":
                self._ip_thresholds()
            return self._bulk()
        return api.asn_whois(value)

    def run(self):
        if self.service not in self.SERVICES:
            self.error("Unknown WhoisFreaks service: {}".format(self.service))
        if self.data_type not in self.SERVICES[self.service]:
            self.notSupported()
        value = self._observable()

        report = {"service": self.service, "observable": value}
        try:
            report["result"] = _expect_dict(self._call(value))
            report["found"] = True
        except NotFoundError as e:
            report["result"] = {}
            report["found"] = False
            report["message"] = str(e)
        except WhoisFreaksError as e:
            self.error(str(e))
        except Exception as e:
            # A response the analyzer cannot read: a message instead of a traceback
            self.error("Unexpected WhoisFreaks response ({}); the lookup may have been billed"
                       .format(e.__class__.__name__))
        if self.query:
            report["query"] = self.query
        if 206 in self.api.statuses:
            report["partial"] = True
        if 210 in self.api.statuses:
            report["cached"] = True
        if self.service in ("ip_reputation", "bulk_ip_reputation"):
            report["thresholds"] = {"malicious": self.ip_malicious,
                                    "suspicious": self.ip_suspicious}
        self._artifacts = self._capped_artifacts(report)
        self.report(report)

    # -- summary -----------------------------------------------------------

    def summary(self, raw):
        taxonomies = []

        def add(level, predicate, value):
            taxonomies.append(self.build_taxonomy(level, NAMESPACE, predicate, value))

        service = raw.get("service")
        result = _dict(raw.get("result"))
        if not raw.get("found"):
            add("info", "Result", "not found")
            return {"taxonomies": taxonomies}

        if service == "whois":
            if result.get("domain_registered") == "no":
                add("info", "Registered", "no")
            else:
                # The registrar WHOIS can be missing; the registry copy then holds the data
                registry = _dict(result.get("registry_data"))
                registrar = (_dict(result.get("domain_registrar")).get("registrar_name")
                             or _dict(registry.get("domain_registrar")).get("registrar_name"))
                if registrar:
                    add("info", "Registrar", registrar)
                created = _created(result)
                if created:
                    age = (date.today() - created).days
                    level = "suspicious" if age < NEW_DOMAIN_DAYS else "info"
                    add(level, "Created", "{} ({} days)".format(created.isoformat(), age))
        elif service == "whois_history":
            total = _int(result.get("total_records"),
                         len(_list(result.get("whois_domains_historical"))))
            add("info", "WhoisHistory", _count(total, "record"))
        elif service == "reverse_whois":
            add("info", "ReverseWhois", _count(_int(result.get("total_Result")), "domain"))
        elif service == "dns":
            add("info", "DNS", _count(len(_list(result.get("dnsRecords"))), "record"))
        elif service == "dns_history":
            add("info", "DNSHistory", _count(_int(result.get("totalRecords")), "record"))
        elif service == "reverse_dns":
            add("info", "ReverseDNS", _count(_int(result.get("totalRecords")), "domain"))
        elif service in REVERSE_RECORD_SERVICES:
            add("info", REVERSE_RECORD_SERVICES[service][1],
                _count(_int(result.get("totalRecords")), "domain"))
        elif service == "domain_reputation":
            risk = _dict(result.get("risk_category"))
            verdict = str(risk.get("verdict") or "unknown")
            add(VERDICT_LEVELS.get(verdict.lower(), "info"), "Verdict", verdict)
            trust = _dict(result.get("trust_signals")).get("trust_score")
            if trust is not None:
                add("info", "TrustScore", trust)
        elif service == "domain_availability":
            availability = str(result.get("availability") or "").upper()
            add("info", "Available", {"AVAILABLE": "yes", "UNAVAILABLE": "no"}.get(
                availability, "unknown"))
        elif service == "tld_availability":
            counts = Counter(str(item.get("availability") or "").upper()
                             for item in _dicts(result.get("bulk_domain_availability_response")))
            add("info", "Available", counts["AVAILABLE"])
            add("info", "Unavailable", counts["UNAVAILABLE"])
        elif service == "ssl":
            certificates = _dicts(result.get("sslCertificates"))
            if not certificates:
                add("info", "SSL", "no certificate")
            else:
                # With ssl_chain the list also holds intermediate and root certificates
                certificate = next((c for c in certificates if c.get("chainOrder") == "end-user"),
                                   certificates[0])
                issuer = _dict(certificate.get("issuer"))
                add("info", "Issuer", issuer.get("organization") or issuer.get("commonName")
                    or "unknown")
                expires = _parse_date(certificate.get("validityEndDate"))
                if expires:
                    expired = expires < date.today()
                    add("suspicious" if expired else "info",
                        "Expired" if expired else "Expires", expires.isoformat())
        elif service == "subdomains":
            add("info", "Subdomains", _int(result.get("total_records")))
        elif service == "typosquatting":
            add("info", "Typosquats", _int(result.get("totalRecords")))
        elif service == "ip_whois":
            organization = _dict(result.get("organization")).get("name")
            if organization:
                add("info", "Org", organization)
            cidrs = [c for net in _dicts(result.get("inet_nums")) for c in _list(net.get("cidr"))]
            if cidrs:
                add("info", "Network", cidrs[0])
        elif service == "ip_reputation":
            security = _dict(result.get("security"))
            score = _int(security.get("threat_score"), None)
            if score is not None:
                if score >= self.ip_malicious:
                    level = "malicious"
                elif score >= self.ip_suspicious:
                    level = "suspicious"
                else:
                    level = "safe"
                add(level, "ThreatScore", score)
            flags = _ip_flags(security)
            if flags:
                level = "malicious" if security.get("is_known_attacker") is True else "suspicious"
                add(level, "Flags", ", ".join(flags))
            context = [label for key, label in IP_CONTEXT_FLAGS if security.get(key) is True]
            if context:
                add("info", "Context", ", ".join(context))
            if score is None and not flags:
                add("info", "ThreatScore", "unknown")
        elif service == "ip_geolocation":
            location = _dict(result.get("location"))
            place = ", ".join(str(x) for x in (location.get("city"), location.get("country_code2"))
                              if x)
            if place:
                add("info", "Location", place)
            asn = _dict(_dict(result.get("network")).get("asn")).get("as_number")
            if asn:
                add("info", "ASN", asn)
        elif service == "asn_whois":
            name = result.get("asName") or result.get("orgName") or ""
            number = ASN_RE.match(str(result.get("asNumber", "")).strip())
            add("info", "ASN", "AS{} {}".format(number.group(1) if number else "?", name).strip())
            if result.get("country"):
                add("info", "Country", result["country"])
        elif service in BULK_SERVICES:
            items = _dicts(result.get("results"))
            ok = [item for item in items if _bulk_ok(service, item)]
            if service == "bulk_whois":
                registered = [item for item in ok if item.get("domain_registered") != "no"]
                new = [item for item in registered if _created(item)
                       and (date.today() - _created(item)).days < NEW_DOMAIN_DAYS]
                add("info", "BulkWhois", _count(len(ok), "domain"))
                if new:
                    add("suspicious", "NewDomains", len(new))
                if len(registered) < len(ok):
                    add("info", "Unregistered", len(ok) - len(registered))
            elif service == "bulk_dns":
                add("info", "BulkDNS", _count(len(ok), "lookup"))
                empty = [item for item in ok if not item.get("dnsRecords")]
                if empty:
                    add("info", "NoRecords", len(empty))
            elif service == "bulk_domain_availability":
                counts = Counter(str(item.get("availability") or "").upper() for item in ok)
                add("info", "Available", counts["AVAILABLE"])
                add("info", "Unavailable", counts["UNAVAILABLE"])
                unknown = len(ok) - counts["AVAILABLE"] - counts["UNAVAILABLE"]
                if unknown:
                    add("info", "Unknown", unknown)
            elif service == "bulk_ip_geolocation":
                add("info", "BulkGeolocation", _count(len(ok), "IP"))
                countries = Counter(_dict(item.get("location")).get("country_code2")
                                    for item in ok)
                countries.pop(None, None)
                if countries:
                    add("info", "Countries", ", ".join(
                        "{} ({})".format(code, n) for code, n in countries.most_common(5)))
            else:
                verdicts = Counter(_ip_verdict(item["security"], self.ip_malicious,
                                               self.ip_suspicious) for item in ok)
                for level, predicate in (("malicious", "Malicious"), ("suspicious", "Suspicious"),
                                         ("safe", "Safe"), ("info", "Unknown")):
                    if verdicts[level]:
                        add(level, predicate, verdicts[level])
            if len(ok) < len(items):
                add("info", "Failed", len(items) - len(ok))
            if _int(result.get("missing")):
                add("info", "Missing", _int(result.get("missing")))
            if result.get("skipped_count"):
                add("info", "Skipped", result["skipped_count"])

        if result.get("error"):
            add("info", "Incomplete", "yes")
        if raw.get("partial"):
            add("info", "Partial", "yes")
        if raw.get("cached"):
            add("info", "Cached", "yes")
        if raw.get("artifacts_truncated"):
            add("info", "Observables", "{} of {}".format(MAX_ARTIFACTS, raw["artifacts_truncated"]))
        if not taxonomies:
            add("info", "Result", "found")
        return {"taxonomies": taxonomies}

    # -- artifacts ---------------------------------------------------------

    def artifacts(self, raw):
        if self._artifacts is None:
            self._artifacts = self._capped_artifacts(raw)
        return self._artifacts

    def _capped_artifacts(self, raw):
        """The suggested observables, at most MAX_ARTIFACTS; the report says when some are cut."""
        if not self.auto_extract or not raw.get("found"):
            return []
        try:
            artifacts = self._artifact_list(raw)
        except Exception as e:
            # Keep the report: an unreadable part of the response only costs its observables
            raw["artifacts_error"] = e.__class__.__name__
            return []
        if len(artifacts) > MAX_ARTIFACTS:
            raw["artifacts_truncated"] = len(artifacts)
            artifacts = artifacts[:MAX_ARTIFACTS]
        return artifacts

    def _artifact_list(self, raw):
        service = raw.get("service")
        result = _dict(raw.get("result"))
        observable = str(raw.get("observable", "")).lower()
        artifacts = []
        seen = set()

        def add(data_type, value, context, *extra_tags):
            if data_type in ("domain", "fqdn"):
                value = _domain(value)
            elif data_type == "ip":
                value = _ip(value)
                if value and not is_public_ip(value):
                    value = None
            elif data_type == "autonomous-system":
                match = ASN_RE.match(str(value).strip()) if isinstance(value, (str, int)) \
                    and not isinstance(value, bool) else None
                value = "AS" + match.group(1) if match else None
            elif data_type == "mail":
                # Redacted WHOIS fields hold placeholder text instead of an address
                value = value.strip() if isinstance(value, str) else None
                if value and not EMAIL_RE.match(value):
                    value = None
            if not value or value.lower() == observable or (data_type, value.lower()) in seen:
                return
            seen.add((data_type, value.lower()))
            artifacts.append(self.build_artifact(data_type, value,
                                                 tags=[NAMESPACE, context] + list(extra_tags)))

        def dns_records(records):
            for record in _dicts(records):
                record_type = record.get("dnsType")
                if record_type in ("A", "AAAA"):
                    add("ip", record.get("address"), "dns-" + record_type.lower())
                elif record_type in ("NS", "CNAME", "PTR"):
                    add("fqdn", record.get("singleName"), "dns-" + record_type.lower())
                elif record_type == "MX":
                    add("fqdn", record.get("target"), "dns-mx")

        def whois_record(record):
            name_servers = (record.get("name_servers")
                            or _dict(record.get("registry_data")).get("name_servers"))
            for server in _list(name_servers):
                add("fqdn", server, "name-server")
            for contact in CONTACTS:
                add("mail", _dict(record.get(contact)).get("email_address"),
                    contact.replace("_", "-"))

        if service == "whois":
            whois_record(result)
        elif service == "whois_history":
            for record in _dicts(result.get("whois_domains_historical")):
                whois_record(record)
        elif service == "reverse_whois":
            for record in _dicts(result.get("whois_domains_historical")):
                add("domain", record.get("domain_name"), "reverse-whois")
        elif service == "dns":
            dns_records(result.get("dnsRecords"))
        elif service == "dns_history":
            for snapshot in _dicts(result.get("historicalDnsRecords")):
                dns_records(snapshot.get("dnsRecords"))
        elif service == "reverse_dns" or service in REVERSE_RECORD_SERVICES:
            for record in _dicts(result.get("reverseDnsRecords")):
                add("fqdn", record.get("domainName"), service.replace("_", "-"))
        elif service == "tld_availability":
            # Registered variants of the name are worth a look; available ones are not
            for item in _dicts(result.get("bulk_domain_availability_response")):
                if str(item.get("availability") or "").upper() == "UNAVAILABLE":
                    add("domain", item.get("domain"), "registered-tld")
        elif service == "domain_reputation":
            for ioc in _dicts(_dict(result.get("intelligence")).get("related_iocs")):
                ioc_type = str(ioc.get("type", ""))
                if ioc_type.startswith("ipv"):
                    add("ip", ioc.get("value"), "related-ioc")
                elif ioc_type == "domain":
                    add("domain", ioc.get("value"), "related-ioc")
        elif service == "ssl":
            for certificate in _dicts(result.get("sslCertificates")):
                names = _dict(_dict(certificate.get("extensions"))
                              .get("subjectAlternativeNames")).get("dnsNames")
                for name in _list(names):
                    add("fqdn", name, "ssl-san")
        elif service == "subdomains":
            for record in _dicts(result.get("subdomains")):
                add("fqdn", record.get("subdomain"), "subdomain")
        elif service == "typosquatting":
            for record in _dicts(result.get("domains")):
                add("domain", record.get("domainName"), "typosquatting")
        elif service == "ip_whois":
            for contact in _dicts(result.get("abuse_contacts")):
                for email in _list(contact.get("email")):
                    add("mail", email, "abuse-contact")
        elif service == "ip_reputation":
            add("autonomous-system", _dict(result.get("asn")).get("as_number"), "asn")
        elif service == "ip_geolocation":
            asn = _dict(_dict(result.get("network")).get("asn")).get("as_number")
            add("autonomous-system", asn, "asn")
        elif service in BULK_SERVICES:
            # Each entry of the file that was looked up, so the analyst can import the list
            context = service.replace("_", "-")
            for item in _dicts(result.get("results")):
                if not _bulk_ok(service, item):
                    continue
                value = _bulk_value(service, item)
                if service == "bulk_ip_reputation":
                    verdict = _ip_verdict(item["security"], self.ip_malicious, self.ip_suspicious)
                    add("ip", value, context, "unknown" if verdict == "info" else verdict)
                elif service == "bulk_ip_geolocation" or (service == "bulk_dns"
                                                          and item.get("ipAddress")):
                    add("ip", value, context)
                else:
                    add("domain", value, context)
        return artifacts


if __name__ == "__main__":
    WhoisFreaksAnalyzer().run()
