#!/usr/bin/env python3
# encoding: utf-8

import re
from collections import Counter

import requests
from cortexutils.analyzer import Analyzer


class TweetFeedAnalyzer(Analyzer):
    BASE_URL = "https://api.tweetfeed.live/v1/ioc"
    USER_AGENT = (
        "Cortex-Analyzers-TweetFeed/1.0 "
        "(+https://github.com/TheHive-Project/Cortex-Analyzers)"
    )
    HASH_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{64})$")
    # TweetFeed IOC type -> Cortex artifact data type
    RELATED_TYPES = {"domain": "domain", "url": "url", "ip": "ip", "md5": "hash", "sha256": "hash"}
    MAX_ARTIFACTS = 50

    def __init__(self):
        Analyzer.__init__(self)

    def _record_type(self, observable):
        """Return the TweetFeed IOC type that matches the observable, or None."""
        if self.data_type == "ip":
            return "ip"
        if self.data_type in ("domain", "fqdn"):
            return "domain"
        if self.data_type == "url":
            return "url"
        if self.data_type == "hash" and self.HASH_RE.match(observable):
            return "md5" if len(observable) == 32 else "sha256"
        return None

    def _query(self, observable):
        # One request per observable. No retry: on HTTP 429 the job fails and the
        # analyst (or the Cortex rate limit) decides when to run it again.
        headers = {"User-Agent": self.USER_AGENT, "Accept": "application/json"}
        try:
            response = requests.get(
                self.BASE_URL, params={"value": observable}, headers=headers, timeout=30
            )
        except requests.exceptions.RequestException as e:
            self.error("Unable to reach TweetFeed: {}".format(e))

        if response.status_code == 429:
            self.error(
                "TweetFeed rate limit reached (HTTP 429). Retry in {} seconds.".format(
                    response.headers.get("Retry-After", "60")
                )
            )
        elif response.status_code == 400:
            self.error(
                "TweetFeed rejected the observable (HTTP 400): {}".format(response.text.strip())
            )
        elif not response.ok:
            self.error("TweetFeed returned HTTP {}".format(response.status_code))

        try:
            data = response.json()
        except ValueError as e:
            self.error("Unable to parse TweetFeed response: {}".format(e))

        if not isinstance(data, dict) or "found" not in data:
            self.error("Unexpected TweetFeed response")

        return data

    @staticmethod
    def _same_type(records, record_type):
        # A domain lookup also returns the URL record for the same host (and the
        # reverse), because the API normalizes both to one key. Count only the
        # records of the observable's own type, so one report is not counted twice.
        return [r for r in records if r.get("type") == record_type] or records

    def run(self):
        observable = self.get_data().strip()
        record_type = self._record_type(observable)

        if record_type is None:
            if self.data_type == "hash":
                self.error("TweetFeed indexes MD5 and SHA256 hashes only.")
            self.notSupported()
            return

        data = self._query(observable)

        records = data.get("records") or []
        archive_records = (data.get("archive") or {}).get("records") or []
        # "found" is true only for the live 365 day window. Older reports are in
        # "archive" and can exist when "found" is false.
        listed = bool(data.get("found") or records or archive_records)

        counted = (
            self._same_type(records, record_type)
            + self._same_type(archive_records, record_type)
        )
        reports = sum(r.get("count") or 0 for r in counted)
        tags = Counter(tag for r in counted for tag in r.get("tags") or [])

        report = dict(data)
        report.update({
            "observable": observable,
            "listed": listed,
            "reports": reports,
            "top_tags": [tag for tag, _ in tags.most_common(10)],
        })
        self.report(report)

    def summary(self, raw):
        taxonomies = []

        if not raw.get("listed"):
            taxonomies.append(self.build_taxonomy("info", "TweetFeed", "Reports", 0))
            return {"taxonomies": taxonomies}

        # TweetFeed IOCs come from posts on X, not from a vetted source:
        # "suspicious" is the highest level this analyzer uses.
        taxonomies.append(
            self.build_taxonomy("suspicious", "TweetFeed", "Reports", raw.get("reports", 0))
        )

        top_tags = raw.get("top_tags") or []
        if top_tags:
            value = ", ".join(top_tags[:3])
            if len(top_tags) > 3:
                value += ", ..."
            taxonomies.append(self.build_taxonomy("info", "TweetFeed", "Tags", value))

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        seen = {(self.data_type, (raw.get("observable") or "").lower())}

        for record in raw.get("records") or []:
            for related in record.get("related") or []:
                if len(artifacts) >= self.MAX_ARTIFACTS:
                    return artifacts
                if not isinstance(related, (list, tuple)) or len(related) != 2:
                    continue
                data_type = self.RELATED_TYPES.get(related[0])
                value = related[1]
                if not data_type or not value or (data_type, value.lower()) in seen:
                    continue
                seen.add((data_type, value.lower()))
                artifacts.append(self.build_artifact(data_type, value, tags=["TweetFeed"]))

        return artifacts


if __name__ == "__main__":
    TweetFeedAnalyzer().run()
