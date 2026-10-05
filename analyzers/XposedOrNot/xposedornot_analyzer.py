#!/usr/bin/env python3
# encoding: utf-8

import re
from urllib.parse import quote

import requests
from cortexutils.analyzer import Analyzer

FREE_API_BASE = "https://api.xposedornot.com"
PLUS_API_BASE = "https://plus-api.xposedornot.com"
USER_AGENT = "XposedOrNot-Cortex-Analyzer/1.0 (+https://github.com/XposedOrNot)"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HTTP_TIMEOUT = 15


class XposedOrNotAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param("config.service", None, "Service parameter is missing")
        self.key = self.get_param("config.key", None)

    def _get(self, url, params=None):
        headers = {"User-Agent": USER_AGENT}
        if self.key:
            headers["x-api-key"] = self.key
        return requests.get(url, params=params, headers=headers, timeout=HTTP_TIMEOUT)

    @staticmethod
    def _to_int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _year(value):
        try:
            return int(str(value)[:4])
        except (TypeError, ValueError):
            return None

    def _normalise_free_analytics(self, data):
        breaches = []
        exposed = data.get("ExposedBreaches") or {}
        for entry in exposed.get("breaches_details") or []:
            breaches.append(
                {
                    "name": entry.get("breach"),
                    "date": entry.get("xposed_date"),
                    "records": self._to_int(entry.get("xposed_records")),
                    "domain": entry.get("domain"),
                    "industry": entry.get("industry"),
                    "logo": entry.get("logo"),
                    "password_risk": entry.get("password_risk"),
                    "verified": entry.get("verified"),
                    "data_classes": [c.strip() for c in str(entry.get("xposed_data") or "").split(";") if c.strip()],
                }
            )
        risk = (data.get("BreachMetrics") or {}).get("risk") or []
        risk_label = risk[0].get("risk_label") if risk and isinstance(risk[0], dict) else None
        risk_score = risk[0].get("risk_score") if risk and isinstance(risk[0], dict) else None
        return breaches, risk_label, risk_score

    def _normalise_plus(self, data):
        breaches = []
        for entry in data.get("breaches") or []:
            breaches.append(
                {
                    "name": entry.get("breach_id"),
                    "date": entry.get("breached_date"),
                    "records": self._to_int(entry.get("xposed_records")),
                    "domain": entry.get("domain"),
                    "industry": entry.get("industry"),
                    "logo": entry.get("logo"),
                    "password_risk": entry.get("password_risk"),
                    "verified": entry.get("verified"),
                    "data_classes": [c.strip() for c in str(entry.get("xposed_data") or "").split(";") if c.strip()],
                }
            )
        return breaches, None, None

    def _build_report(self, breaches, risk_label, risk_score):
        if not breaches:
            return {"found": False, "count": 0}
        years = [y for y in (self._year(b.get("date")) for b in breaches) if y]
        report = {
            "found": True,
            "count": len(breaches),
            "first_year": min(years) if years else None,
            "latest_year": max(years) if years else None,
            "total_records": sum(b.get("records") or 0 for b in breaches),
            "risk_label": risk_label,
            "risk_score": risk_score,
            "plaintext_exposure": any(b.get("password_risk") == "plaintextpassword" for b in breaches),
        }
        if self.service == "check_email":
            report["breaches"] = [b["name"] for b in breaches if b.get("name")]
        else:
            report["breaches"] = breaches
        return report

    def run(self):
        email = str(self.get_data() or "").strip().lower()
        if not EMAIL_RE.match(email) or len(email) > 254:
            self.error("The observable is not a valid email address.")
            return

        try:
            if self.key:
                response = self._get(
                    "{}/v3/check-email/{}".format(PLUS_API_BASE, quote(email, safe="")),
                    params={"detailed": "true"},
                )
            elif self.service == "check_email":
                response = self._get("{}/v1/check-email/{}".format(FREE_API_BASE, quote(email, safe="")))
            elif self.service == "breach_analytics":
                response = self._get("{}/v1/breach-analytics".format(FREE_API_BASE), params={"email": email})
            else:
                self.error("Unknown service: {}".format(self.service))
                return

            if response.status_code == 404:
                self.report({"found": False, "count": 0})
                return
            if response.status_code == 429:
                self.error(
                    "XposedOrNot rate limit reached (keyless: 2 requests/second, 25/hour)."
                    " Retry later or configure the optional API key to raise limits."
                )
                return
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.HTTPError as http_error:
            self.error("XposedOrNot API returned HTTP status {}.".format(http_error.response.status_code))
            return
        except requests.exceptions.RequestException as request_error:
            self.error("XposedOrNot API request failed: {}".format(request_error))
            return
        except ValueError:
            self.error("XposedOrNot API returned an invalid JSON response.")
            return

        if self.key:
            breaches, risk_label, risk_score = self._normalise_plus(data)
        elif self.service == "check_email":
            names = [name for group in (data.get("breaches") or []) for name in group]
            breaches = [{"name": name} for name in names]
            risk_label, risk_score = None, None
        else:
            breaches, risk_label, risk_score = self._normalise_free_analytics(data)

        self.report(self._build_report(breaches, risk_label, risk_score))

    def summary(self, raw):
        taxonomies = []
        namespace = "XON"
        count = raw.get("count", 0)
        level = "safe" if count == 0 else "suspicious"
        taxonomies.append(self.build_taxonomy(level, namespace, "Breaches", count))
        if raw.get("risk_label"):
            taxonomies.append(self.build_taxonomy("info", namespace, "Risk", raw["risk_label"]))
        if raw.get("plaintext_exposure"):
            taxonomies.append(self.build_taxonomy("malicious", namespace, "PlaintextPwd", "yes"))
        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        seen = set()
        for breach in raw.get("breaches") or []:
            if not isinstance(breach, dict):
                continue
            domain = breach.get("domain")
            if domain and domain not in seen:
                seen.add(domain)
                artifacts.append(self.build_artifact("domain", domain))
        return artifacts


if __name__ == "__main__":
    XposedOrNotAnalyzer().run()
