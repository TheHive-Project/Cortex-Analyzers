#!/usr/bin/env python3
# encoding: utf-8
"""Cortex analyzer for the IPGeolocation.io v3 API.

One program serves every flavor; `config.service` selects the lookup:

- location: geolocation of an IP address or domain (/v3/ipgeo)
- security: threat score and VPN, proxy, Tor, bot and spam signals (/v3/security)
- asn: an autonomous system, looked up by AS number or IP address (/v3/asn)
- abuse: the abuse contact of the network an IP address belongs to (/v3/abuse)
- user_agent: client, device and operating system of a user agent (/v3/user-agent)
"""

import ipaddress
import re
import time
from urllib.parse import quote

import requests
from cortexutils.analyzer import Analyzer

DEFAULT_BASE_URL = "https://api.ipgeolocation.io"
CLIENT_USER_AGENT = (
    "IPGeolocation-Cortex/1.0 (+https://github.com/TheHive-Project/Cortex-Analyzers)"
)
NAMESPACE = "IPGeolocation"

# Observable types each service accepts.
SERVICES = {
    "location": ("ip", "domain", "fqdn"),
    "security": ("ip",),
    "asn": ("ip", "autonomous-system"),
    "abuse": ("ip",),
    "user_agent": ("user-agent",),
}

# Threat score bands: below the suspicious threshold the score is shown as
# info, never safe. A low score means no risk signals were found, which is not
# a clearance, and a green tag in a triage queue reads as one.
DEFAULT_SUSPICIOUS_THRESHOLD = 21
DEFAULT_MALICIOUS_THRESHOLD = 51

# Credits are only charged on HTTP 200, so gateway errors and failed
# connections are retried. Read timeouts are not: the API may already have
# served, and charged for, the request.
RETRY_STATUSES = (502, 503, 504)
MAX_RETRIES = 2

STATUS_HINTS = {
    400: "Invalid request",
    401: "Not authorized",
    404: "Not found",
    413: "Request too large",
    423: "Bogon or private IP address",
    429: "API credit limit reached",
}

# The API's web server rejects header lines over 8 KB (8,000 characters was
# verified to work), and only printable ASCII is safe in a header. Longer or
# non-ASCII user agents go in a POST body instead, which needs a paid plan.
MAX_HEADER_USER_AGENT = 8000
HEADER_SAFE = re.compile(r"[\t\x20-\x7e]*")

DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
ASN_PATTERN = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)

# The user agent API gives attack tools (sqlmap, Nikto, the Nmap scripting
# engine...) the type "Hacker". A user agent is trivially spoofed, so this is
# suspicious, not malicious.
SUSPICIOUS_USER_AGENT_TYPES = ("hacker",)
# Placeholders the user agent API uses for unknown values.
UNKNOWN_VALUES = ("", "??", "unknown")

# Security flags shown as tags when set: (flag, tag, field holding a better value).
SECURITY_FLAGS = (
    ("is_tor", "Tor", None),
    ("is_vpn", "VPN", "vpn_provider_names"),
    ("is_proxy", "Proxy", "proxy_provider_names"),
    ("is_residential_proxy", "ResidentialProxy", None),
    ("is_relay", "Relay", "relay_provider_name"),
    ("is_known_attacker", "KnownAttacker", None),
    ("is_bot", "Bot", "bot_type"),
    ("is_known_good_bot", "KnownGoodBot", "bot_operator_name"),
    ("is_spam", "Spam", None),
    ("is_cloud_provider", "CloudProvider", "cloud_provider_name"),
    ("is_corporate_gateway", "CorporateGateway", "corporate_gateway_provider_name"),
)


class InputError(ValueError):
    """The observable cannot be looked up as given."""


class ApiError(Exception):
    """The API call failed; the message is safe to show to analysts."""


class IPGeolocationAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            "config.service", None, "IPGeolocation.io service is missing"
        )
        if self.service not in SERVICES:
            self.error("Unknown IPGeolocation.io service: {}".format(self.service))

        self.api_key = str(self.get_param("config.api_key", "") or "").strip()
        if not self.api_key:
            self.error("IPGeolocation.io API key is missing")

        self.base_url = str(
            self.get_param("config.base_url", None) or DEFAULT_BASE_URL
        ).rstrip("/")
        self.timeout = self._number("timeout", 30, minimum=1)
        self.suspicious_threshold = self._number(
            "suspicious_threshold", DEFAULT_SUSPICIOUS_THRESHOLD, minimum=0
        )
        self.malicious_threshold = self._number(
            "malicious_threshold", DEFAULT_MALICIOUS_THRESHOLD, minimum=0
        )
        if self.malicious_threshold < self.suspicious_threshold:
            self.error(
                "malicious_threshold ({}) must not be lower than suspicious_threshold ({})".format(
                    self.malicious_threshold, self.suspicious_threshold
                )
            )

        self.session = requests.Session()
        self.session.headers.update(
            {"Accept": "application/json", "User-Agent": CLIENT_USER_AGENT}
        )

    def _number(self, name, default, minimum):
        value = self.get_param("config." + name, None)
        if value is None or value == "":
            return default
        try:
            number = int(float(value))
        except (TypeError, ValueError, OverflowError):
            self.error("{} must be a number, got '{}'".format(name, value))
        if number < minimum:
            self.error("{} must be at least {}, got {}".format(name, minimum, number))
        return number

    # --- Lookups ------------------------------------------------------------

    def run(self):
        supported = SERVICES[self.service]
        if self.data_type not in supported:
            self.error(
                "The IPGeolocation.io {} lookup does not support '{}' observables "
                "(supported: {}).".format(
                    self.service, self.data_type, ", ".join(supported)
                )
            )
        try:
            result = getattr(self, "_lookup_" + self.service)(self.get_data())
        except (InputError, ApiError) as error:
            self.error(str(error))
        self.report(result)

    def _lookup_location(self, data):
        if self.data_type == "ip":
            target = validate_ip(data)
        else:
            target = validate_domain(data)
        return self._request("GET", "/v3/ipgeo", params={"ip": target})

    def _lookup_security(self, data):
        result = self._request("GET", "/v3/security", params={"ip": validate_ip(data)})
        security = section(result, "security")
        # Stored in the report so the long template colours the score the same
        # way as the short report.
        result["threat_level"] = self.threat_level(security.get("threat_score"))
        return result

    def _lookup_asn(self, data):
        if self.data_type == "autonomous-system":
            params = {"asn": normalize_asn(data)}
        else:
            params = {"ip": validate_ip(data)}
        return self._request("GET", "/v3/asn", params=params)

    def _lookup_abuse(self, data):
        return self._request("GET", "/v3/abuse", params={"ip": validate_ip(data)})

    def _lookup_user_agent(self, data):
        user_agent = str(data or "").strip()
        if not user_agent:
            raise InputError("The user agent is empty.")
        if fits_in_header(user_agent):
            return self._request(
                "GET", "/v3/user-agent", headers={"User-Agent": user_agent}
            )
        return self._request("POST", "/v3/user-agent", body={"uaString": user_agent})

    # --- HTTP ---------------------------------------------------------------

    def _request(self, method, path, params=None, headers=None, body=None):
        query = dict(params or {})
        # The API key is a query parameter, the only server-side auth method
        # the API offers, so every message built from a request is redacted.
        query["apiKey"] = self.api_key
        url = self.base_url + path

        for attempt in range(MAX_RETRIES + 1):
            last_attempt = attempt == MAX_RETRIES
            try:
                response = self.session.request(
                    method,
                    url,
                    params=query,
                    headers=headers,
                    json=body,
                    timeout=self.timeout,
                )
            except requests.exceptions.ConnectionError as error:
                if last_attempt:
                    raise ApiError(
                        "Could not connect to IPGeolocation.io: {}".format(
                            self._redact(error)
                        )
                    )
            except requests.exceptions.Timeout:
                raise ApiError(
                    "IPGeolocation.io did not answer within {} seconds".format(
                        self.timeout
                    )
                )
            except requests.exceptions.RequestException as error:
                raise ApiError(
                    "Request to IPGeolocation.io failed: {}".format(self._redact(error))
                )
            else:
                if response.status_code not in RETRY_STATUSES or last_attempt:
                    return self._handle(response)
            time.sleep(2**attempt)

    def _handle(self, response):
        status = response.status_code
        if status == 200:
            try:
                data = response.json()
            except ValueError:
                raise ApiError("IPGeolocation.io returned a response that is not JSON.")
            if not isinstance(data, dict):
                raise ApiError("IPGeolocation.io returned data in an unexpected format.")
            return data

        message = ""
        try:
            payload = response.json()
            if isinstance(payload, dict):
                message = str(payload.get("message") or "")
        except ValueError:
            pass
        hint = STATUS_HINTS.get(status)
        if hint is None:
            hint = "IPGeolocation.io service error" if status >= 500 else "Unexpected response"
        detail = "{} (HTTP {})".format(hint, status)
        if message:
            detail += ": " + self._redact(message)
        elif status == 401:
            detail += ": check the API key and that your plan includes this lookup"
        raise ApiError(detail)

    def _redact(self, value):
        text = str(value)
        for secret in {self.api_key, quote(self.api_key, safe="")}:
            text = text.replace(secret, "***")
        return text

    # --- Report -------------------------------------------------------------

    def threat_level(self, score):
        try:
            score = int(score)
        except (TypeError, ValueError):
            return "info"
        if score >= self.malicious_threshold:
            return "malicious"
        if score >= self.suspicious_threshold:
            return "suspicious"
        return "info"

    def summary(self, raw):
        taxonomies = []

        def tag(predicate, value, level="info"):
            if value is None or value == "" or value == []:
                return
            taxonomies.append(self.build_taxonomy(level, NAMESPACE, predicate, value))

        getattr(self, "_summary_" + self.service)(raw, tag)
        return {"taxonomies": taxonomies}

    def _summary_location(self, raw, tag):
        location = section(raw, "location")
        asn = section(raw, "asn")
        if raw.get("domain"):
            tag("IP", raw.get("ip"))
        tag("Country", location.get("country_name") or location.get("country_code2"))
        tag("ASN", asn.get("as_number"))
        tag("Org", asn.get("organization"))

    def _summary_security(self, raw, tag):
        security = section(raw, "security")
        score = security.get("threat_score")
        if score is None:
            tag("ThreatScore", "unknown")
            return
        tag("ThreatScore", score, raw.get("threat_level") or self.threat_level(score))
        for flag, predicate, detail in SECURITY_FLAGS:
            if security.get(flag) is True:
                value = text_value(security.get(detail)) if detail else None
                tag(predicate, value or "true")

    def _summary_asn(self, raw, tag):
        asn = section(raw, "asn")
        tag("ASN", asn.get("as_number"))
        tag("Org", asn.get("organization"))
        tag("Type", asn.get("type"))

    def _summary_abuse(self, raw, tag):
        abuse = section(raw, "abuse")
        emails = abuse_emails(raw)
        if emails:
            more = len(emails) - 1
            tag("Email", emails[0] + (" (+{} more)".format(more) if more else ""))
        tag("Org", abuse.get("organization") or abuse.get("name"))
        if not emails and not (abuse.get("organization") or abuse.get("name")):
            tag("Abuse", "no contact found")

    def _summary_user_agent(self, raw, tag):
        ua_type = known(raw.get("type"))
        level = "info"
        if ua_type and ua_type.lower() in SUSPICIOUS_USER_AGENT_TYPES:
            level = "suspicious"
        tag("Type", ua_type, level)
        name = known(raw.get("name"))
        if name and name != ua_type:
            version = known(raw.get("version"))
            tag("Client", "{} {}".format(name, version) if version and version != name else name)
        os_name = known(section(raw, "operating_system").get("name"))
        if os_name != ua_type:
            tag("OS", os_name)
        device = known(section(raw, "device").get("type"))
        if device != ua_type:
            tag("Device", device)

    def artifacts(self, raw):
        if not self.auto_extract:
            return []
        artifacts = []
        if self.service == "location" and raw.get("domain") and raw.get("ip"):
            artifacts.append(
                self.build_artifact(
                    "ip",
                    str(raw["ip"]),
                    message="IP address {} resolved to (IPGeolocation.io)".format(raw["domain"]),
                )
            )
        if self.service in ("location", "asn") and self.data_type != "autonomous-system":
            match = ASN_PATTERN.match(str(section(raw, "asn").get("as_number") or ""))
            if match:
                artifacts.append(
                    self.build_artifact(
                        "autonomous-system",
                        match.group(1),
                        message="Autonomous system (IPGeolocation.io)",
                    )
                )
        if self.service == "abuse":
            for email in abuse_emails(raw):
                artifacts.append(
                    self.build_artifact(
                        "mail", email, message="Abuse contact (IPGeolocation.io)"
                    )
                )
        return artifacts


def section(data, key):
    """A nested object of the response, or an empty dict when absent or malformed."""
    value = data.get(key) if isinstance(data, dict) else None
    return value if isinstance(value, dict) else {}


def text_value(value):
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value if v)
    return str(value) if value else None


def abuse_emails(raw):
    """The abuse emails, trimmed and without duplicates: the API can pad them with spaces."""
    emails = []
    for email in section(raw, "abuse").get("emails") or []:
        email = email.strip() if isinstance(email, str) else ""
        if email and email not in emails:
            emails.append(email)
    return emails


def known(value):
    """The value, or None for the placeholders the API uses for unknown."""
    if value is None or str(value).strip().lower() in UNKNOWN_VALUES:
        return None
    return str(value).strip()


def validate_ip(value):
    candidate = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        raise InputError("'{}' is not a valid IPv4 or IPv6 address.".format(candidate))


def validate_domain(value):
    candidate = str(value or "").strip().rstrip(".").lower()
    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_domain = ""
    labels = ascii_domain.split(".")
    if len(labels) < 2 or not all(DOMAIN_LABEL.match(label) for label in labels):
        raise InputError("'{}' is not a valid domain name.".format(candidate))
    # The API only resolves internationalized domains in their punycode form.
    return ascii_domain


def normalize_asn(value):
    match = ASN_PATTERN.match(str(value or "").strip())
    if not match:
        raise InputError(
            "'{}' is not a valid AS number (for example AS15169 or 15169).".format(value)
        )
    return "AS{}".format(int(match.group(1)))


def fits_in_header(user_agent):
    """Whether a user agent can be sent in the User-Agent header."""
    return (
        len(user_agent) <= MAX_HEADER_USER_AGENT
        and HEADER_SAFE.fullmatch(user_agent) is not None
    )


if __name__ == "__main__":
    IPGeolocationAnalyzer().run()
