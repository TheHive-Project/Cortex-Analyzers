#!/usr/bin/env python3
# encoding: utf-8

import hashlib
import math
import time
from typing import Literal, Optional, TypedDict

import requests
from cortexutils.analyzer import Analyzer


class Sample(TypedDict):
    mcap_id: str  # Unique identifier for the sample
    filename: str  # Name of the file submitted
    created_at: str  # The date and time the file was submitted
    private: bool  # Whether the submission was declared private or not
    source: int  # Malware source the submission was declared with
    note: str  # Note the sample was submitted with
    user: str  # Username of the user who submitted the sample


class SubmitResponse(TypedDict):
    message: str  # Message confirming upload was successful
    sample: Sample


class SampleStatus(TypedDict):
    # The sample ID, globally unique, and the canonical identifier of this
    # sample analysis.
    id: str
    # A numeric identifier of the submission, not globally unique. Some devices
    # which submitted via the V1 api will only have this available. Deprecated.
    submission_id: int
    # The filename for the sample, as provided or derived from the submission.
    filename: str
    # The state of the sample, one of a stable set of strings "pending,
    # running, succ, proc, fail".
    state: Literal["pending", "running", "succ", "proc", "fail"]
    # A detailed status of the sample.
    status: str
    # The sha256 hash of the sample.
    sha256: str
    # The md5 hash of the sample, if available.
    md5: str
    # The sha1 hash of the sample, if available.
    sha1: str
    # A string identifying the OS, as provided by the submitter.
    os: str
    # A string identifying the OS version, as provided by the submitter.
    osver: str
    # If the sample is marked private, will have the boolean value, true.
    private: str
    # The time at which the sample was submitted(ISO 8601).
    submitted_at: str
    # The time the sample analysis was started(ISO 8601).
    started_at: str
    # The time the sample analysis was completed(ISO 8601).
    completed_at: str


class MCAPAnalyzer(Analyzer):
    @staticmethod
    def get_file_hash(
            file_path: str,
            blocksize: int = 8192,
            algorithm=hashlib.sha256):
        file_hash = algorithm()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(blocksize), b""):
                file_hash.update(chunk)
        return file_hash.hexdigest()

    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param(
            'config.key', None, "Missing API Key")
        self.private_samples = self.get_param(
            'config.private_samples', None,
            "Missing private_samples config")
        self.minimum_confidence = self.get_param(
            'config.minimum_confidence', 80)
        self.minimum_severity = self.get_param(
            'config.minimum_severity', 80)
        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.max_sample_result_wait = self.get_param(
            'max_sample_result_wait', 1000)
        self.api_root = "https://mcap.cisecurity.org/api"

        self.session = requests.Session()
        self.session.verify = True
        self.session.proxies = self.get_param('config.proxy', None)
        self.session.headers.update({
            'Accept': 'application/json',
            'Authorization': f"Bearer {self.api_key}"
        })

    def _check_for_api_errors(self, response: requests.Response,
                              error_prefix="", good_status_code=200):
        """Check for API a failure response and exit with error if needed"""
        if response.status_code != good_status_code:
            message = None
            try:
                response_dict = response.json()
                if 'message' in response_dict:
                    errors = str(response_dict.get('errors', ''))
                    message = "{} {}{}".format(
                        error_prefix, response_dict['message'], errors)
            except requests.exceptions.JSONDecodeError:
                pass

            if message is None:
                message = "{} HTTP {} {}".format(
                    error_prefix, response.status_code, response.text)
            self.error(message)

    def submit_file(self, file_path: str) -> SubmitResponse:
        """Upload a file to MCAP and return the sample's tracking info

        Args:
            file_path: Full path to the file to be uploaded

        Returns:
            SubmitResponse
        """
        url = self.api_root + "/sample/submit"
        data = {
            "private": 1 if self.private_samples else 0,
            "source": 6,  # Other/Unknown
            "email_notification": 0
        }
        files = {"sample_file": open(file_path, mode='rb')}
        try:
            response = self.session.post(url, data=data, files=files)
            self._check_for_api_errors(
                response,
                "While submitting file:")
        except requests.RequestException as e:
            self.error('Error while trying to submit file: ' + str(e))
        submit_response: SubmitResponse = response.json()
        return submit_response

    def get_sample_status(
            self,
            mcap_id: Optional[str] = None,
            sha256: Optional[str] = None) -> Optional[SampleStatus]:
        """Get the status of a previously submitted sample

        Note that even after a sample is submitted, this function can still
        return None for several minutes until the analysis has been completed.

        Args:
            mcap_id: unique MCAP integer ID of the sample used to check status
            sha256: SHA-256 hash of the submitted sample

        Returns:
            Return the sample status if it was found, else None
        """
        request_url = self.api_root + "/sample/status"
        assert(mcap_id is not None or sha256 is not None)

        request_params = {}
        if mcap_id is not None:
            request_params.update({"mcap_id": mcap_id})
        else:
            request_params.update({"sha256": sha256})

        try:
            response = self.session.get(request_url, params=request_params)
            self._check_for_api_errors(
                response,
                "While getting sample status:")
        except requests.RequestException as e:
            self.error('Error while trying to get sample status: ' + str(e))

        status = response.json()
        if len(status) > 0:
            return status[0]
        return None

    def check_feed(self, data_type: str, data) -> list[dict]:
        """Return a list of known IOCs for an observable"""

        # First figure out the request parameters
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
        elif data_type == 'hash' and len(data) != 64:
            self.error(
                "This API only supports SHA-256 hashes which have 64"
                f" characters. Your hash '{data}' has {len(data)}")
        elif data_type == 'hash':
            feed_name = 'artifacts'
            request_data['sha256'] = data
        else:
            self.error(f"Cannot check feed for {data_type=}")

        # Now we can make the API request
        url = f"{self.api_root}/feeds/{feed_name}"
        try:
            response = self.session.get(url, params=request_data)
            self._check_for_api_errors(response, "While checking feed:")
            iocs = response.json()
        except requests.RequestException as e:
            self.error('Error while trying to get check feed: ' + str(e))

        if isinstance(iocs, dict):
            # The IP feed was observed to return a dictionary keyed by the
            # string representation of the list index, so this special case
            # ensures that our return value is always a list.
            return list(iocs.values())
        return iocs

    def summary(self, full_report: dict):
        """Build taxonomies from the report data to give an IOC count"""
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
        if self.data_type not in [
                "ip", "hash", "url", "domain", "fqdn", "file"]:
            self.error(f"Unsupported data type {self.data_type}")

        if self.data_type != "file":
            data = self.get_param('data', None, 'Missing data field')
            iocs = self.check_feed(self.data_type, str.strip(data))
            return self.report({'iocs': iocs})
        # else the data type "file" is implied

        filepath = self.get_param('file', None, 'File is missing')
        sample_identifier = {'sha256': self.get_file_hash(filepath)}
        sample_status = self.get_sample_status(**sample_identifier)
        if sample_status is None:
            submit_response = self.submit_file(filepath)
            mcap_id = submit_response['sample']['mcap_id']
            sample_identifier = {'mcap_id': mcap_id}

        # Loop until we get sample results or time out
        tries = 0
        max_tries = math.ceil(
            self.max_sample_result_wait // self.polling_interval)
        while ((sample_status is None and tries <= max_tries)
               or sample_status['state'] in ["pending", "running"]):
            time.sleep(self.polling_interval)
            sample_status = self.get_sample_status(**sample_identifier)
            tries += 1

        if sample_status is None:
            self.error(f"No sample status received after {tries} tries.")
        if sample_status['state'] in ["pending", "running"]:
            self.error(
                f"Gave up polling for pending sample after {tries} tries."
                f" Last status details: {sample_status['status']}"
                f" | Unique sample id: {sample_status['id']}")

        self.report({
            'sample_status': sample_status,
            'iocs': self.check_feed('hash', sample_status['sha256'])
        })


if __name__ == '__main__':
    MCAPAnalyzer().run()
