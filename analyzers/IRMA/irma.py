#!/usr/bin/env python
# encoding: utf-8

import time
import hashlib
import requests
import urlparse
from requests.auth import HTTPBasicAuth

from cortexutils.analyzer import Analyzer


class IRMAAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.url = self.get_param('config.url', None, 'IRMA URL parameter is missing')
        self.timeout = self.get_param('config.timeout', 60)
        self.scan = self.get_param('config.scan', 1)
        self.force = self.get_param('config.force', 1)
        self.verify = self.get_param('config.verify', True)
        self.time_start = time.time()
        self.username = self.get_param('config.username', None)
        self.password = self.get_param('config.password', None)

        if self.username is None:
            self.auth = None
        else:
            self.auth = HTTPBasicAuth(self.username, self.password)

    def summary(self, raw):
        total = 0
        findings = 0
        if 'probe_results' in raw:
            anti_viruses = filter(lambda analysis: analysis["type"] == 'antivirus', raw["probe_results"])
            total = len(anti_viruses)

            malicious = filter(lambda analysis: analysis["status"] == 1, anti_viruses)
            findings = len(malicious)

        return {
            'taxonomies': [self.build_taxonomy(
                'safe' if findings == 0 else 'malicious',
                'IRMA',
                'Scan',
                '0' if total == 0 else '{}/{}'.format(findings, total)
            )]
        }

        return result

    """Gets anti virus signatures from IRMA for various results.
       Currently obtains IRMA results for the target sample.
       """
    # IRMA statuses https://github.com/quarkslab/irma-cli/blob/master/irma/apiclient.py
    IRMA_FINISHED_STATUS = 50
    ERROR_STATUS = {
        1000: "Unexpected error",
        1010: "probelist missing",
        1011: "probe(s) not available",
        1020: "ftp upload error"
    }

    def _request_json(self, url, **kwargs):
        """Wrapper around doing a request and parsing its JSON output."""
        try:
            r = requests.get(url, timeout=self.timeout, verify=self.verify, auth=self.auth, **kwargs)
            return r.json() if r.status_code == 200 else {}
        except (requests.ConnectionError, ValueError) as e:
            self.unexpectedError(e)

    def _post_json(self, url, **kwargs):
        """Wrapper around doing a post and parsing its JSON output."""
        try:
            r = requests.post(url, timeout=self.timeout, verify=self.verify, auth=self.auth, **kwargs)
            return r.json() if r.status_code == 200 else {}
        except (requests.ConnectionError, ValueError) as e:
            self.unexpectedError(e)

    # IRMA statuses https://github.com/quarkslab/irma-cli/blob/master/irma/apiclient.py
    def _is_error_status(self, status):
        return status >= 1000

    def _scan_file(self, file_name, file_path, force):
        # Initialize scan in IRMA.
        init = self._post_json(urlparse.urljoin(self.url, "/api/v1.1/scans"))

        # Post file for scanning.
        files = {
            "files": (file_name, open(file_path, "rb")),
        }
        url = urlparse.urljoin(
            self.url, "/api/v1.1/scans/%s/files" % init.get("id")
        )
        self._post_json(url, files=files)

        # launch posted file scan
        params = {
            "force": force,
        }
        url = urlparse.urljoin(
            self.url, "/api/v1.1/scans/%s/launch" % init.get("id")
        )
        requests.post(url, json=params, verify=self.verify, auth=self.auth)

        result = None
        timeout_exceeded = False

        while result is None or result.get("status") != self.IRMA_FINISHED_STATUS and not timeout_exceeded:
            url = urlparse.urljoin(
                self.url, "/api/v1.1/scans/%s" % init.get("id")
            )
            result = self._request_json(url)

            if result is not None and self._is_error_status(result.get("status")):
                self.error('An error occurred during the file scan: {}'.format(
                    self.ERROR_STATUS.get(result.get("status"), "Unexpected error"))
                )

            time.sleep(10)
            timeout_exceeded = time.time() >= self.time_start + self.timeout

        if timeout_exceeded:
            self.error('The {} seconds timeout has been exceeded')

        return

    def _get_results(self, sha256):
        # Fetch list of scan IDs.
        results = self._request_json(
            urlparse.urljoin(self.url, "/api/v1.1/files/%s" % sha256)
        )

        if not results.get("items"):
            return

        result_id = results["items"][-1]["result_id"]
        return self._request_json(
            urlparse.urljoin(self.url, "/api/v1.1/results/%s" % result_id)
        )

    def run(self):
        if self.service == 'scan':
            if self.data_type == 'file':
                file_name = self.get_param('attachment.name', 'noname.ext')
                file_path = self.get_param('file', None, 'File is missing')
                hashes = self.get_param('attachment.hashes', None)

                if hashes is None:
                    file_hash = hashlib.sha256(open(file_path, 'r').read()).hexdigest()
                else:
                    # find SHA256 hash
                    file_hash = next(h for h in hashes if len(h) == 64)

                # Fetch the result from IRMA using the file's hash
                results = self._get_results(file_hash)

                if not self.force and not self.scan and not results:
                    return {}
                elif self.force or (not results and self.scan):
                    self._scan_file(file_name, file_path, self.force)
                    results = self._get_results(file_hash) or {}

                """ FIXME! could use a proper fix here
                        that probably needs changes on IRMA side aswell
                        --
                        related to  https://github.com/elastic/elasticsearch/issues/15377
                        entropy value is sometimes 0 and sometimes like  0.10191042566270775
                        other issue is that results type changes between string and object :/
                        """
                for idx, result in enumerate(results["probe_results"]):
                    if result["name"] == "PE Static Analyzer":
                        results["probe_results"][idx]["results"] = None

                self.report(results)

            else:
                self.error('Invalid data type')
        else:
            self.error('Invalid service')


if __name__ == '__main__':
    IRMAAnalyzer().run()
