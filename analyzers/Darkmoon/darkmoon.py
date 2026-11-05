#!/usr/bin/env python3
# encoding: utf-8

import re
from urllib.parse import urlparse

import requests
from cortexutils.analyzer import Analyzer

SEVERITIES = ["info", "low", "medium", "high", "critical"]
PROVEN_STATUSES = ("exploited", "confirmed")


def host_of(value):
    """Return the lowercase host of a URL, host:port, domain or IP (None if empty)."""
    value = (value or "").strip()
    if not value:
        return None
    if "://" not in value:
        value = "//" + value
    try:
        host = urlparse(value).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def normalize_severity(value):
    value = str(value or "").strip().lower()
    return value if value in SEVERITIES else "info"


def normalize_status(value):
    value = str(value or "").strip().lower()
    if "remediat" in value or "fixed" in value:
        return "remediated"
    if "exploit" in value:
        return "exploited"
    if "confirm" in value and "unconfirm" not in value:
        return "confirmed"
    return "unconfirmed"


def campaign_host(campaign):
    """Best effort host of a campaign (target, host, target_stack.host or report_path)."""
    for candidate in (
        campaign.get("target"),
        campaign.get("host"),
        (campaign.get("target_stack") or {}).get("host")
        if isinstance(campaign.get("target_stack"), dict)
        else None,
    ):
        host = host_of(candidate)
        if host:
            return host
    match = re.search(
        r"pentest_report_(.+)_\d{8}-\d{4,6}\.md$", str(campaign.get("report_path") or "")
    )
    return host_of(match.group(1)) if match else None


class DarkmoonAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        base = self.get_param("config.url", None, "Missing Darkmoon API URL").strip().rstrip("/")
        if base.endswith("/api/v1"):
            base = base[: -len("/api/v1")]
        self.api_base = base + "/api/v1"
        self.token = (self.get_param("config.token", "") or "").strip()
        self.username = self.get_param("config.username", "") or ""
        self.password = self.get_param("config.password", "") or ""
        self.verify_ssl = self.get_param("config.verify_ssl", True)
        self.min_severity = normalize_severity(self.get_param("config.min_severity", "info"))
        self.include_unconfirmed = self.get_param("config.include_unconfirmed", True)
        try:
            self.max_findings = int(self.get_param("config.max_findings", 100))
        except (TypeError, ValueError):
            self.max_findings = 100
        self.session = requests.Session()
        self.session.verify = bool(self.verify_ssl)
        self.session.headers["Accept"] = "application/json"

    def _authenticate(self):
        if self.token:
            self.session.headers["Authorization"] = "Bearer " + self.token
            return
        if not (self.username and self.password):
            self.error(
                "Darkmoon credentials missing: set either the token or the username and password"
            )
        try:
            response = self.session.post(
                self.api_base + "/auth/login",
                json={"username": self.username, "password": self.password},
                timeout=30,
            )
        except requests.exceptions.RequestException as e:
            self.error("Unable to reach Darkmoon: {}".format(e))
        if response.status_code != 200:
            self.error("Darkmoon login failed (HTTP {})".format(response.status_code))
        try:
            token = response.json().get("token")
        except ValueError:
            token = None
        if not token:
            self.error("Darkmoon login returned no token")
        self.session.headers["Authorization"] = "Bearer " + token

    def _get(self, path, params=None):
        try:
            response = self.session.get(self.api_base + path, params=params, timeout=30)
        except requests.exceptions.RequestException as e:
            self.error("Unable to reach Darkmoon: {}".format(e))
        if response.status_code in (401, 403):
            self.error("Darkmoon rejected the credentials (HTTP {})".format(response.status_code))
        if not response.ok:
            self.error("Darkmoon returned HTTP {} for {}".format(response.status_code, path))
        try:
            body = response.json()
        except ValueError as e:
            self.error("Unable to parse the Darkmoon response: {}".format(e))
        data = body.get("data") if isinstance(body, dict) else body
        return data if isinstance(data, list) else []

    def _collect(self, host):
        campaigns = self._get("/campaigns")
        matched = [c for c in campaigns if campaign_host(c) == host]
        raw = {}
        for campaign in matched:
            for finding in self._get("/vulnerabilities", {"campaign_id": campaign.get("id")}):
                raw[str(finding.get("id") or finding.get("node_id") or id(finding))] = finding
        # Findings of campaigns whose target is not exposed in the list, matched on endpoint host.
        for finding in self._get("/vulnerabilities"):
            if host_of(finding.get("endpoint")) == host:
                raw[str(finding.get("id") or finding.get("node_id") or id(finding))] = finding
        return matched, list(raw.values())

    def _shape(self, finding):
        remediation = finding.get("remediation")
        if isinstance(remediation, dict):
            remediation = remediation.get("summary")
        return {
            "id": finding.get("id") or finding.get("node_id"),
            "campaign_id": finding.get("campaign_id"),
            "title": finding.get("title"),
            "severity": normalize_severity(finding.get("severity")),
            "status": normalize_status(finding.get("status")),
            "category": finding.get("category"),
            "cve": finding.get("cve"),
            "cvss_score": finding.get("cvss_score"),
            "mitre_attack_id": finding.get("mitre_attack_id"),
            "endpoint": finding.get("endpoint"),
            "discovered_by_agent": finding.get("discovered_by_agent"),
            "discovered_at": finding.get("discovered_at"),
            "remediation": remediation,
        }

    def run(self):
        if self.data_type not in ("url", "domain", "fqdn", "ip"):
            self.notSupported()
            return
        observable = self.get_data()
        host = host_of(observable)
        if not host:
            self.error("Unable to extract a host from the observable")

        self._authenticate()
        campaigns, raw_findings = self._collect(host)

        floor = SEVERITIES.index(self.min_severity)
        findings = [self._shape(f) for f in raw_findings]
        findings = [
            f
            for f in findings
            if SEVERITIES.index(f["severity"]) >= floor
            and (self.include_unconfirmed or f["status"] != "unconfirmed")
        ]
        findings.sort(
            key=lambda f: (-SEVERITIES.index(f["severity"]), -(f["cvss_score"] or 0), f["title"] or "")
        )
        total = len(findings)
        by_severity = {s: 0 for s in reversed(SEVERITIES)}
        for f in findings:
            by_severity[f["severity"]] += 1

        self.report(
            {
                "observable": observable,
                "host": host,
                "campaigns": [
                    {
                        "id": c.get("id"),
                        "status": c.get("status"),
                        "overall_risk": c.get("overall_risk"),
                        "date": c.get("date") or c.get("created_at"),
                    }
                    for c in campaigns
                ],
                "total": total,
                "proven": sum(1 for f in findings if f["status"] in PROVEN_STATUSES),
                "by_severity": by_severity,
                "truncated": total > self.max_findings,
                "findings": findings[: self.max_findings],
            }
        )

    def summary(self, raw):
        taxonomies = []
        total = raw.get("total", 0)
        by_severity = raw.get("by_severity", {})
        proven = raw.get("proven", 0)

        level = "info"
        if by_severity.get("critical") or by_severity.get("high"):
            level = "malicious"
        elif by_severity.get("medium"):
            level = "suspicious"
        taxonomies.append(self.build_taxonomy(level, "Darkmoon", "Findings", total))
        if total:
            taxonomies.append(
                self.build_taxonomy("malicious" if proven else "info", "Darkmoon", "Proven", proven)
            )
            for severity in ("critical", "high"):
                if by_severity.get(severity):
                    taxonomies.append(
                        self.build_taxonomy(
                            "malicious", "Darkmoon", severity.capitalize(), by_severity[severity]
                        )
                    )
        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        # Findings are not observables; avoid auto-extracting the URLs found in descriptions.
        return []


if __name__ == "__main__":
    DarkmoonAnalyzer().run()
