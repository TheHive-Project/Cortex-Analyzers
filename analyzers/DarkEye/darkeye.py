#!/usr/bin/env python3
# encoding: utf-8

import re
import unicodedata

import requests
from cortexutils.analyzer import Analyzer

USER_AGENT = "darkeye-cortex/1.0 (+https://github.com/TheHive-Project/Cortex-Analyzers)"

HIBR = "HaveIBeenRansom"
HIBR_URL = "https://haveibeenransom.com/api/metadata/domain"
# leak_type values used by the HaveIBeenRansom metadata endpoint.
HIBR_CATEGORIES = {"ransomware_leak": "ransomware", "traditional_breach": "breach"}
DEFAULT_MAX_PAGES = 5
DEFAULT_MAX_RECORDS = 100

BREACH_HOUSE = "Breach House"
BREACH_HOUSE_URL = "https://breach.house/api/v1/search"
# Sources of the Breach House search, and the category each record gets.
BREACH_HOUSE_CATEGORIES = {
    "ransomware": "ransomware",
    "breaches": "breach",
    "leads": "leads",
    "stealers": "stealer",
}
DEFAULT_LIMIT = 25
MAX_LIMIT = 200

# Both APIs treat * and ? as wildcards, so only plain domain names are queried.
DOMAIN_REGEX = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


class DarkEyeError(Exception):
    """A product lookup failed. The message is safe to show to analysts."""


def clean(value):
    """Return a NFKC-normalised single-line string, or "" for non-text values.

    Some group and source names use styled Unicode characters and irregular spacing.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return ""
    return " ".join(unicodedata.normalize("NFKC", str(value)).split())


def to_int(value, default, minimum=1, maximum=None):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    number = max(minimum, number)
    return min(number, maximum) if maximum else number


class DarkEyeAnalyzer(Analyzer):
    """Look up a domain in DarkEye: HaveIBeenRansom and Breach House.

    One analyzer for both products. Each has its own optional API key and the
    analyzer queries every product that has one. When one product fails the
    records of the other are kept and the failure is listed in `errors`; the job
    only fails when every configured product failed.

    Only listing metadata is kept for each record. Leaked content, proof files,
    leak-site URLs and download links are never read from the responses.
    """

    def __init__(self):
        Analyzer.__init__(self)
        self.hibr_key = (self.get_param("config.haveibeenransom_api_key", "") or "").strip()
        self.breach_house_key = (self.get_param("config.breachhouse_api_key", "") or "").strip()
        self.max_pages = to_int(self.get_param("config.max_pages", DEFAULT_MAX_PAGES), DEFAULT_MAX_PAGES)
        self.max_records = to_int(
            self.get_param("config.max_records", DEFAULT_MAX_RECORDS), DEFAULT_MAX_RECORDS
        )
        self.limit = to_int(
            self.get_param("config.limit", DEFAULT_LIMIT), DEFAULT_LIMIT, maximum=MAX_LIMIT
        )
        self.timeout = to_int(self.get_param("config.timeout", 30), 30)

    # --- HTTP ---------------------------------------------------------------

    def _get_json(self, product, url, api_key, params=None):
        try:
            response = requests.get(
                url,
                params=params,
                headers={
                    "Authorization": "Bearer {}".format(api_key),
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException:
            # Request exceptions can carry request details: never pass them on.
            raise DarkEyeError("{} request failed or timed out.".format(product)) from None

        if response.status_code != 200:
            if response.status_code in (401, 403):
                message = "{} authentication failed; check its API key.".format(product)
            elif response.status_code == 429:
                message = "{} quota or rate limit reached; retry later.".format(product)
            else:
                message = "{} returned HTTP {}.".format(product, response.status_code)
            raise DarkEyeError(message)
        try:
            data = response.json()
        except ValueError:
            raise DarkEyeError("{} returned invalid JSON.".format(product)) from None
        if not isinstance(data, dict):
            raise DarkEyeError("{} returned an invalid response.".format(product))
        return data

    # --- records ------------------------------------------------------------

    @staticmethod
    def _record(product, category, item):
        """Keep only listing metadata of an API item."""
        website = clean(item.get("website"))
        return {
            "product": product,
            "category": category,
            "id": clean(item.get("victim_id") or item.get("id_source") or item.get("id")),
            "title": clean(item.get("post_title")) or clean(item.get("name")) or website,
            "website": website,
            "group": clean(item.get("group_name")),
            "country": clean(item.get("country")),
            "discovered": clean(item.get("discovered"))[:10],
        }

    @staticmethod
    def _mentions_domain(record, domain):
        """True when a Breach House record is about the domain, not just near it.

        The search matches free text, so a record whose website is another domain
        only mentions the target. With a website, it must be the domain or one of
        its subdomains. Without one, the title is free text and the domain must
        stand alone as a hostname: not inside notexample.com or
        example.com.other.com, but still as mail.example.com.
        """
        website = record["website"].lower().rstrip(".")
        if website:
            return website == domain or website.endswith("." + domain)
        title = record["title"].lower()
        pattern = r"(?<![\w-]){}(?![\w-]|\.\w)".format(re.escape(domain))
        return bool(title) and re.search(pattern, title) is not None

    def _fetch_hibr(self, domain):
        """HaveIBeenRansom leaks of a domain, and whether a limit cut the list short."""
        records = []
        seen = set()
        for page in range(1, self.max_pages + 1):
            url = "{}/{}".format(HIBR_URL, domain)
            if page > 1:
                url = "{}/{}".format(url, page)
            data = self._get_json(HIBR, url, self.hibr_key)
            # The API returns "sources" and a top-level "has_next"; its docs show
            # "results" and "pagination".
            pagination = data.get("pagination")
            if not isinstance(pagination, dict):
                pagination = {}
            for leak in data.get("sources") or data.get("results") or []:
                if not isinstance(leak, dict):
                    continue
                # A leak indexed while paging is repeated on a later page.
                leak_id = clean(leak.get("id_source") or leak.get("id"))
                if not leak_id or leak_id in seen:
                    continue
                seen.add(leak_id)
                leak_type = clean(leak.get("leak_type"))
                category = HIBR_CATEGORIES.get(leak_type, leak_type or "leak")
                records.append(self._record(HIBR, category, leak))
            has_next = data.get("has_next", pagination.get("has_next", False))
            # A page can be short or empty and still have a next page.
            if len(records) > self.max_records:
                return records[: self.max_records], True
            if not has_next:
                return records, False
            if len(records) == self.max_records:
                return records, True
        return records, True

    def _fetch_breach_house(self, domain):
        """Breach House records of a domain, and whether a limit cut the list short."""
        data = self._get_json(
            BREACH_HOUSE,
            BREACH_HOUSE_URL,
            self.breach_house_key,
            params={"q": domain, "limit": self.limit},
        )
        records = []
        truncated = False
        for source, category in BREACH_HOUSE_CATEGORIES.items():
            section = data.get(source)
            # Each source is {"results": [...], "total": n}; a bare list is accepted too.
            total = None
            if isinstance(section, dict):
                total = section.get("total")
                section = section.get("results")
            if not isinstance(section, list):
                continue
            if len(section) >= self.limit or (
                isinstance(total, int) and not isinstance(total, bool) and total > len(section)
            ):
                truncated = True
            for item in section:
                if not isinstance(item, dict):
                    continue
                record = self._record(BREACH_HOUSE, category, item)
                if self._mentions_domain(record, domain):
                    records.append(record)
        if len(records) > self.max_records:
            return records[: self.max_records], True
        return records, truncated

    # --- Cortex -------------------------------------------------------------

    def _domain(self):
        value = str(self.get_data()).strip().lower().rstrip(".")
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            pass
        if not DOMAIN_REGEX.match(value) or value.rsplit(".", 1)[-1].isdigit():
            self.error("A plain domain name is required.")
        return value

    def run(self):
        if self.data_type not in ("domain", "fqdn"):
            self.notSupported()

        products = []
        if self.hibr_key:
            products.append((HIBR, self._fetch_hibr))
        if self.breach_house_key:
            products.append((BREACH_HOUSE, self._fetch_breach_house))
        if not products:
            self.error(
                "Configure haveibeenransom_api_key or breachhouse_api_key to use this analyzer."
            )

        domain = self._domain()
        records = []
        answered = []
        errors = []
        truncated = False
        for product, fetch in products:
            # One product failing does not discard the other product's records.
            try:
                product_records, product_truncated = fetch(domain)
            except DarkEyeError as error:
                errors.append({"product": product, "error": str(error)})
                continue
            answered.append(product)
            records.extend(product_records)
            truncated = truncated or product_truncated

        if not answered:
            # An empty report would read as "nothing found" when nothing was asked.
            self.error(" ".join(error["error"] for error in errors))

        by_product = {product: 0 for product in answered}
        by_category = {}
        for record in records:
            by_product[record["product"]] += 1
            by_category[record["category"]] = by_category.get(record["category"], 0) + 1

        self.report(
            {
                "observable": domain,
                "found": bool(records),
                "count": len(records),
                "products": answered,
                "counts_by_product": by_product,
                "counts_by_category": by_category,
                "truncated": truncated,
                "errors": errors,
                "records": records,
            }
        )

    def artifacts(self, raw):
        # Records describe other organisations. Turning their websites and titles
        # into observables would add domains the analyst never asked about.
        return []

    def summary(self, raw):
        namespace = "DarkEye"
        count = raw.get("count") or 0
        taxonomies = []

        # Deliberately never "malicious" and never "safe". A record means the
        # domain appears in leaked or listed data, usually as a victim, which
        # is not the same as the domain being hostile. No record only means
        # nothing was found, not that the domain is clean.
        value = "{}+".format(count) if raw.get("truncated") else count
        taxonomies.append(
            self.build_taxonomy("suspicious" if count else "info", namespace, "Records", value)
        )
        if raw.get("errors"):
            taxonomies.append(
                self.build_taxonomy("info", namespace, "Errors", len(raw["errors"]))
            )
        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    DarkEyeAnalyzer().run()
