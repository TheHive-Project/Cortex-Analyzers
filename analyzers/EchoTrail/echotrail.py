#!/usr/bin/env python3
# encoding: utf-8

import hashlib
from typing import Tuple, TypedDict

import requests
from cortexutils.analyzer import Analyzer

ItemPrevalence = Tuple[str, str]  # The second is a stringified float


class InsightResult(TypedDict):
    # Note: Some of these fields may be optional and not actually present
    rank: int
    host_prev: float
    eps: float
    description: str
    intel: str
    paths: list[ItemPrevalence]
    parents: list[ItemPrevalence]
    children: list[ItemPrevalence]
    grandparents: list[ItemPrevalence]
    hashes: list[ItemPrevalence]
    network: list[ItemPrevalence]


class EchoTrailAnalyzer(Analyzer):
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
        self.api_root = "https://api.echotrail.io/v1/private"

        self.session = requests.Session()
        self.session.verify = True
        self.session.proxies = self.get_param('config.proxy', None)
        self.session.headers.update({
            'Accept': 'application/json',
            'X-Api-key': self.api_key
        })

    def _check_for_api_errors(self, response: requests.Response,
                              error_prefix="", good_status_code=200):
        """Check for API a failure response and exit with error if needed"""
        if response.status_code != good_status_code:
            message = None
            try:
                response_dict = response.json()
                if 'message' in response_dict:
                    message = "{} {}".format(
                        error_prefix, response_dict['message'])
            except requests.exceptions.JSONDecodeError:
                pass

            if message is None:
                message = "{} HTTP {} {}".format(
                    error_prefix, response.status_code, response.text)
            self.error(message)

    def get_insights(self, search_term: str) -> InsightResult:
        url = f"{self.api_root}/insights/{search_term}"
        try:
            response = self.session.get(url)
            self._check_for_api_errors(response)
            return response.json()
        except requests.RequestException as e:
            self.error('Error while trying to get insights: ' + str(e))

    def summary(self, full_report: dict):
        """Build taxonomies from the report data to give an IOC count"""
        taxonomies = []
        namespace = "EchoTrail"
        keys = ["rank", "host_prev", "eps"]
        level = "info"
        for k in keys:
            if k not in full_report:
                continue
            taxonomies.append(
                self.build_taxonomy(level, namespace, k, full_report[k]))
        return {"taxonomies": taxonomies}

    def run(self):
        data = self.get_param('data', None, 'Missing data field')
        if self.data_type == "hash":
            if len(data) != 32 and len(data) != 64:
                self.error(
                    f"The input hash has an invalid length ({len(data)})."
                    " It should be 32 (MD5) or 64 (SHA-256) characters.")

        result = self.get_insights(data)
        if len(result) == 1 and 'message' in result:
            result['matched'] = False
        else:
            result['matched'] = True

        self.report(result)


if __name__ == '__main__':
    EchoTrailAnalyzer().run()
