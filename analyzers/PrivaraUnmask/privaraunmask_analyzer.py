#!/usr/bin/env python3
# encoding: utf-8
"""Cortex analyzer for Privara Unmask: C2 extraction from Android malware.

The analyzer looks the file's SHA-256 up first (GET /jobs?sha256=, free) and
reuses a charged result (live / dead, last 30 days) or waits for a running job;
otherwise it uploads the file (APK, XAPK, APKM or .apks), polls the job and
reports the outcome, the malware family and the C2 servers with their liveness
check. C2 values are defanged in the report; the raw values are returned as
artifacts (url / ip / domain) so TheHive can add them as observables.

Every analysis can be charged on the customer's Privara wallet: uploads carry
an Idempotency-Key made from the file's SHA-256, so running the analyzer again
on the same file never charges twice. After a none / void / failed result the
file is analysed again under a key derived from that earlier job. Job ids are
opaque: read from the API's JSON, never parsed or validated.
"""

import hashlib
import io
import ipaddress
import os
import zipfile

from cortexutils.analyzer import Analyzer
from privara_unmask_client import (
    DEFAULT_BASE_URL,
    REFUSED_REASONS,
    UnmaskClient,
    UnmaskError,
    UnmaskTimeout,
    dashboard_url,
    defang,
    idempotency_key,
    liveness_text,
    outcome_label,
)

NAMESPACE = "PrivaraUnmask"
OUTCOME_LEVEL = {
    "live": "malicious",
    "dead": "suspicious",
    "none": "info",
    "void": "info",
}


def android_package_kind(content):
    """Return 'apk' / 'bundle' when the bytes look like an Android package, else None."""
    if not content.startswith(b"PK\x03\x04"):
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = archive.namelist()
    except (zipfile.BadZipFile, ValueError):
        return None
    if "AndroidManifest.xml" in names:
        return "apk"
    if any(name.lower().endswith(".apk") for name in names):
        return "bundle"
    return None


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def c2_artifact(entry):
    """TheHive (dataType, data, port) for one C2, from the API's kind / host / port fields.

    ``kind`` is ``url | ip | domain | host_port``; returns None for anything else.
    """
    kind = (entry.get("kind") or "").lower()
    value = (entry.get("value") or "").strip()
    host = (entry.get("host") or "").strip().strip("[]")
    port = entry.get("port") if isinstance(entry.get("port"), int) else None
    if kind == "url" and value:
        return "url", value, None
    if kind == "ip":
        return "ip", host or value, None
    if kind == "domain":
        return "domain", host or value, None
    if kind == "host_port" and host:
        return ("ip" if is_ip(host) else "domain"), host, port
    return None


def known_to(entry):
    """abuse.ch feeds that already list this C2 (information only), or None."""
    intel = entry.get("intel")
    if not isinstance(intel, dict) or not intel.get("known"):
        return None
    feeds = ", ".join(str(f) for f in intel.get("feeds") or []) or "abuse.ch"
    malware = str(intel.get("malware") or "").strip()
    return feeds + (" ({})".format(malware) if malware else "")


def percent(value):
    if isinstance(value, (int, float)) and 0 <= value <= 1:
        return int(round(value * 100))
    return None


def dollars(cents):
    return "${:.2f}".format((cents or 0) / 100)


class PrivaraUnmaskAnalyzer(Analyzer):
    def __init__(self, job_directory=None):
        Analyzer.__init__(self, job_directory)
        self.api_key = self.get_param(
            "config.api_key", None, "Privara Unmask API key is missing"
        )
        self.api_url = self.get_param("config.api_url", None) or DEFAULT_BASE_URL
        self.max_wait = int(self.get_param("config.max_wait", None) or 1500)
        self.poll_interval = int(self.get_param("config.poll_interval", None) or 30)
        self.max_file_mb = self.get_param("config.max_file_size_mb", None)
        self._c2_raw = []

    def make_client(self):
        return UnmaskClient(
            api_key=self.api_key, base_url=self.api_url, integration="thehive"
        )

    # ------------------------------------------------------------- summary

    def summary(self, raw):
        taxonomies = []
        outcome = raw.get("outcome")
        if not outcome:
            # queued / running (timeout), failed or canceled: no outcome, never charged
            status = raw.get("status") or "unknown"
            taxonomies.append(self.build_taxonomy("info", NAMESPACE, "Status", status))
            return {"taxonomies": taxonomies}
        taxonomies.append(
            self.build_taxonomy(
                OUTCOME_LEVEL.get(outcome, "info"), NAMESPACE, "Outcome", outcome
            )
        )
        c2 = raw.get("c2") or []
        c2_level = "info"
        if c2:
            c2_level = (
                "malicious" if any(entry.get("live") for entry in c2) else "suspicious"
            )
        taxonomies.append(self.build_taxonomy(c2_level, NAMESPACE, "C2", len(c2)))
        family = (raw.get("family") or {}).get("name")
        if family:
            taxonomies.append(
                self.build_taxonomy("malicious", NAMESPACE, "Family", family)
            )
        return {"taxonomies": taxonomies}

    # ----------------------------------------------------------- artifacts

    def artifacts(self, raw):
        """Raw C2 values as observables. Rejected candidates are never returned."""
        if not self.auto_extract:
            return []
        artifacts = []
        seen = set()
        for entry in self._c2_raw:
            found = c2_artifact(entry)
            if found is None:
                continue
            data_type, data, port = found
            if not data or (data_type, data) in seen:
                continue
            seen.add((data_type, data))
            tags = [
                "privara-unmask",
                "c2",
                "c2-live" if entry.get("live") else "c2-dead",
            ]
            if port:
                tags.append("port:{}".format(port))
            message = "C2 extracted by Privara Unmask ({}, confidence {}%)".format(
                entry.get("source") or "analysis", percent(entry.get("confidence"))
            )
            artifacts.append(
                self.build_artifact(data_type, data, tags=tags, message=message)
            )
        return artifacts

    # ----------------------------------------------------------------- run

    def build_report(self, job, reused=False):
        """The long report: everything defanged, no raw C2 value."""
        family = job.get("family") or {}
        return {
            "job_id": job.get("job_id"),
            "status": job.get("status"),
            "outcome": job.get("outcome"),
            "outcome_text": outcome_label(job),
            "charge_cents": job.get("charge_cents") or 0,
            "charge": dollars(job.get("charge_cents")),
            "reused": reused,
            "family": (
                {
                    "name": family.get("name"),
                    "confidence": percent(family.get("confidence")),
                }
                if family.get("name")
                else None
            ),
            "sample": {
                "filename": job.get("filename"),
                "sha256": job.get("sha256"),
                "package": job.get("package"),
            },
            "android": job.get("android") or {},
            "c2": [
                {
                    "defanged": entry.get("defanged")
                    or defang(entry.get("value") or ""),
                    "kind": entry.get("kind"),
                    "port": entry.get("port"),
                    "live": bool(entry.get("live")),
                    "liveness": liveness_text(entry),
                    "confidence": percent(entry.get("confidence")),
                    "source": entry.get("source"),
                    "intel": known_to(entry),
                }
                for entry in job.get("c2") or []
            ],
            "rejected_count": len(job.get("rejected_candidates") or []),
            "web_url": job.get("web_url"),
        }

    def config_error(self, err, submitting=False):
        """Stop with a clear message for errors the user must fix."""
        if err.code == "invalid_key" or err.status == 401:
            self.error(
                "Privara Unmask: the API key is invalid or revoked. Check the analyzer's api_key."
            )
        if err.code == "missing_scope":
            self.error(
                "Privara Unmask: the API key lacks a scope; it needs submit and read."
            )
        if err.code == "not_found" and submitting:
            self.error(
                "Privara Unmask: the Unmask API is not enabled for this Privara account "
                "(or api_url is wrong)."
            )
        if err.code == "not_found":
            self.error("Privara Unmask: the job was not found for this API key.")
        self.error("Privara Unmask API error: {}".format(err))

    def submit_error(self, err):
        if err.status == 402:
            self.error(
                "Privara Unmask: wallet balance too low, nothing was queued or charged ({}). "
                "Top up at {} and run the analyzer again.".format(
                    err.message, dashboard_url(self.api_url)
                )
            )
        if err.status == 403 and err.code == "fair_use_reached":
            self.error(
                "Privara Unmask: monthly fair-use limit reached, nothing was charged ({}).".format(
                    err.message
                )
            )
        if err.status == 413:
            self.error(
                "Privara Unmask: the file is too large for Privara ({}).".format(
                    err.message
                )
            )
        if err.status == 429:
            self.error(
                "Privara Unmask: rate limited, nothing was sent or charged ({}). "
                "Run the analyzer again in a few minutes.".format(err.message)
            )
        self.config_error(err, submitting=True)

    def max_file_bytes(self, client):
        """The API's limit (GET /balance), lowered by max_file_size_mb when set."""
        try:
            limit = client.max_file_bytes()
        except UnmaskError as err:
            self.config_error(err)
        if self.max_file_mb:
            limit = min(limit, int(self.max_file_mb) * 1024 * 1024)
        return limit

    def existing_job(self, client, sha256):
        """(job to reuse or wait for, earlier job not reused) for this sample."""
        try:
            return client.lookup(sha256)
        except UnmaskError as err:
            if err.transient:
                return None, None
            self.config_error(err)

    def run(self):
        if self.data_type != "file":
            self.notSupported()
        filepath = self.get_param("file", None, "File is missing")
        filename = self.get_param("filename", None) or os.path.basename(filepath)
        try:
            client = self.make_client()
        except ValueError as err:
            self.error("Privara Unmask configuration error: {}".format(err))
        max_bytes = self.max_file_bytes(client)
        if os.path.getsize(filepath) > max_bytes:
            self.error(
                "Not sent to Privara: the file is larger than the {} MB limit.".format(
                    max_bytes // 1048576
                )
            )
        with open(filepath, "rb") as handle:
            content = handle.read()
        if android_package_kind(content) is None:
            self.error(
                "Not sent to Privara: the file is not an Android package (APK, XAPK, APKM or .apks)."
            )

        sha256 = hashlib.sha256(content).hexdigest()
        job, earlier = self.existing_job(client, sha256)
        reused = job is not None
        submitted = job is None
        if job is None:
            try:
                answer = client.submit_sample(
                    filename,
                    content,
                    idempotency_key=idempotency_key(
                        "cortex", sha256, earlier.get("job_id") if earlier else None
                    ),
                    label="TheHive " + filename,
                )
            except UnmaskError as err:
                self.submit_error(err)
            jobs = answer.get("jobs") or []
            if not jobs:
                self.error("Privara Unmask accepted the upload but returned no job.")
            job = jobs[0]
            if job.get("status") == "refused":
                refused = job.get("refused") or {}
                code = refused.get("code") or "refused"
                self.error(
                    "Privara refused the file, nothing was charged: {} (code {}). {}".format(
                        REFUSED_REASONS.get(code, "it was refused"),
                        code,
                        refused.get("message") or "",
                    ).strip()
                )

        # The server matched an earlier charged result of this sample: no new charge.
        duplicate = bool(job.get("duplicate_of"))
        result = job
        # A submit answer is only a summary (even when it says done, for a
        # duplicate): always read the full job. wait_for_job reads it at once.
        if submitted or job.get("status") != "done":
            try:
                result = client.wait_for_job(
                    job["job_id"],
                    max_wait=self.max_wait,
                    initial_interval=self.poll_interval,
                )
            except UnmaskTimeout as err:
                report = self.build_report(err.job)
                report["message"] = (
                    "The analysis is still running on Privara after {} s. Run the analyzer "
                    "again later to collect the result: the same job is found again and "
                    "nothing is charged twice.".format(int(err.waited))
                )
                self.report(report)
                return
            except UnmaskError as err:
                self.config_error(err)
            reused = duplicate

        self._c2_raw = result.get("c2") or []
        self.report(self.build_report(result, reused=reused))


if __name__ == "__main__":
    PrivaraUnmaskAnalyzer().run()
