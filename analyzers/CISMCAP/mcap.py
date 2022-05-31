#!/usr/bin/env python3
# encoding: utf-8

import hashlib
import json
import time
from typing import BinaryIO, Tuple, TypedDict

import requests
import xmltodict
from cortexutils.analyzer import Analyzer


class Sample(TypedDict):
    mcap_id: str  # Unique identifier for the sample
    filename: str  # Name of the file submitted
    created_at: str  # The date and time the file was submitted
    private: bool  # Whether the submission was declared private or not
    source: str  # Malware source the submission was declared with
    note: str  # Note the sample was submitted with
    user: str  # Username of the user who submitted the sample


class SubmitResponse(TypedDict):
    message: str  # Message confirming upload was successful
    sample: Sample


class MCAPAnalyzer(Analyzer):
    def _check_for_api_errors(self, response: requests.Response,
                              error_prefix=""):
        """Requests response processing hook"""
        if response.status_code != 200:
            # TODO: response.json() and look for 'message' key
            self.error("{} HTTP {} {}".format(
                error_prefix, response.status_code, response.text))

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None,
                                      'MCAP service is missing')
        self.api_key = self.get_param(
            'config.key', None, "Missing API Key")
        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.api_root = "https://mcap.cisecurity.org/api"
        self.session = requests.Session()
        # TODO: Add back proxy support
        self.session.headers.update({
            'Accept': 'application/json',
            'Authorization': f"Bearer {self.api_key}"
        })

    def submit_file(self, file_path: str, filename="sample") -> SubmitResponse:
        """TODO: FIXME"""
        url = self.api_root + "/sample/submit"
        private = 1 if self.private_samples else 0
        data = dict(sample_file=file_path, private=private)
        files = dict(file=(filename, open(file_path, mode='rb')))
        try:
            response = self.session.post(url, data=data, files=files)
            self._check_for_api_errors(
                response,
                "While submitting file:")
        except requests.RequestException as e:
            self.error('Error while trying to submit file: ' + str(e))
        return response.json()

    def get_sample_status(self, **kwargs) -> dict:
        """TODO: FIXME"""
        request_url = self.api_root + "/sample/status"
        # Available parameters:
        #   mcap_id - - unique MCAP id of the sample ex: 1
        #   mcap_ids - - comma separated list of unique MCAP sample ids ex: 1, 2 tg_id - - unique ThreatGrid id of the sample ex:
        #   tg_ids - - comma seperated list of unique ThreatGrid ids
        #   sha256 - - A sha256 of the submitted sample, only matches samples, not their artifacts.
        #   md5 - - As above, but an MD5 checksum.
        #   sha1 - - As above, but a SHA1 checksum
        try:
            response = self.session.post(request_url, data=kwargs)
            self._check_for_api_errors(
                response,
                "While getting sample status:")
        except requests.RequestException as e:
            self.error('Error while trying to get sample status: ' + str(e))

        return response.json()

    def check_feed(self, data_type: str, data):
        request_data = {
            'confidence': self.minimum_confidence,
            'severity': self.minimum_severity
        }
        if data_type == 'ip':
            feed_name = 'ips'
            request_data['ip'] = data
        elif data_type in ['domain', 'fqdn']:
            feed_name = 'domains'
            request_data['domain'] = data
        elif data_type == 'url':
            feed_name = 'urls'
            request_data['url'] = data
        elif data_type == 'hash':
            if len(data) != 64:
                self.error(
                    "This API only supports SHA-256 hashes which have 64"
                    f" characters. Your hash '{data}' has {len(data)}")
            feed_name = 'artifacts'
            request_data['sha256'] = data
        else:
            self.error(f"Cannot check feed for {data_type=}")

        url = f"{self.api_root}/feeds/{feed_name}"
        try:
            response = self.session.get(url, params=request_data)
            self._check_for_api_errors(response, "While checking feed:")
        except requests.RequestException as e:
            self.error('Error while trying to get check feed: ' + str(e))
        return response.json()

    def summary(self, full_report: dict):
        """Build taxonomies from the report data to give a summary"""
        taxonomies = []
        namespace = "CISMCAP"
        predicate = "IOC count"
        ioc_count = len(full_report['iocs'])
        if ioc_count > 0:
            level = "malicious"
        else:
            level = "safe"
        taxonomies.append(
            self.build_taxonomy(level, namespace, predicate, ioc_count))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.service not in ['feed', 'scan']:
            self.error(f"Unknown service {self.service}")

        if self.service == 'feed':
            self.minimum_confidence = self.get_param(
                'config.minimum_confidence', 80)
            self.minimum_severity = self.get_param(
                'config.minimum_severity', 80)
            data = self.get_param('data', None, 'Missing data field')
            iocs = self.check_feed(self.data_type, str.strip(data))
            return self.report({'iocs': iocs})

        # 'scan' service is implied
        self.private_samples = self.get_param(
            'config.private_samples', None, "Missing private_samples config")
        filename = self.get_param('filename', 'sample')
        filepath = self.get_param('file', None, 'File is missing')
        submit_response = self.submit_file(filepath, filename)

        # with open(filepath, 'rb') as f:
        #     # Calculate SHA-256 hash locally so we can see if it's known
        #     data = self.get_file_hash(f)
        # verdict, verdict_int = self.get_verdict('hash', data)
        # if verdict_int < 0 and verdict != 'pending':
        #     result = self.submit_file(filepath, filename)
        #     verdict = verdict_int = None
        #     print(f"Result of submit_file: {result}")
        #     data = result['sha256']

        # tries = 0
        # while verdict in [None, "pending"] and tries <= 20:
        #     time.sleep(self.polling_interval)
        #     verdict, verdict_int = self.get_verdict(self.data_type, data)
        #     tries += 1
        # if verdict == "pending":
        #     self.error("WildFire API analysis timed out. Please try again")
        # if verdict == "error":
        #     self.error("WildFire API returned error")
        self.report({'info': "Not yet implemented"})  # TODO


if __name__ == '__main__':
    MCAPAnalyzer().run()
