#!/usr/bin/env python3
# encoding: utf-8

import hashlib
import json
import time
from typing import BinaryIO, Tuple

import requests
import xmltodict
from cortexutils.analyzer import Analyzer


class WildFireAnalyzer(Analyzer):
    @staticmethod
    def get_file_hash(
            f: BinaryIO,
            blocksize: int = 8192,
            algorithm=hashlib.sha256):
        file_hash = algorithm()
        for chunk in iter(lambda: f.read(blocksize), b""):
            file_hash.update(chunk)
        return file_hash.hexdigest()

    def _check_for_api_errors(self, response: requests.Response, error_prefix=""):
        """Requests response processing hook"""
        if response.headers['content-type'].lower() == "text/xml" and len(
                response.text) > 0:
            results = xmltodict.parse(response.text)
            if "error" in results.keys():
                self.error("{}({}) {}".format(
                    error_prefix, response.status_code,
                    results["error"]["error-message"]))
        if response.status_code != 200:
            self.error(error_prefix + self._errors[response.status_code])

    def __init__(self, proxies=None, verify=True):
        """Initializes the WildFire class

        Args:
            proxies (dict): An optional dictionary containing proxy data, with
            https as the key, and the proxy path
            as the value
            verify (bool): Verify the certificate
            verify (str): A path to a CA cert bundle
        """
        Analyzer.__init__(self)
        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.api_key = self.get_param(
            'config.key', None, "Missing WildFire API Key")
        self.api_host = self.get_param(
            'config.api_host', None, "Missing WildFire API host")
        self.api_root = f"https://{self.api_host}/publicapi"
        self.session = requests.Session()
        self.session.proxies = proxies
        self.session.verify = verify

    _errors = {
        401: "API key is invalid",
        403: "Permission denied. This can occur when attempting to "
             "download benign or greyware samples.",
        404: "Not found",
        405: "Method other than POST used",
        413: "Sample file size over max limit",
        418: "Sample file type is not supported",
        419: "Max calls per day reached",
        420: "Insufficient arguments. Ensure the request has the required request parameters.",
        421: "Invalid argument",
        422: "The provided file or URL cannot be processed. The URl can't be downloaded or the file has formatting "
             "errors or invalid content.",
        500: "Internal WildFire error",
        513: "File upload failed"
    }

    _verdicts = {
        0: "benign",
        1: "malware",
        2: "greyware",
        4: "phishing",
        -100: "pending",
        -101: "error",
        -102: "not found",
        -103: "invalid hash"
    }

    # Here we have a list of report sub-keys that we need to process in the
    # listify_report_objects function.
    # '*' means the previous key is a list of objects to iterate over
    # '**' means the previous key is a dictionary and we need to process all of
    # the values.
    _listify_wildfire_report_keys = [
        "task_info.report",
        "task_info.report.*.summary.entry",
        "task_info.report.*.timeline.entry",
        "task_info.report.*.network.TCP",
        "task_info.report.*.network.UDP",
        "task_info.report.*.network.dns",
        "task_info.report.*.process_list.process",
        "task_info.report.*.process_list.process.*.child.process",
        "task_info.report.*.process_list.process.*.process_activity.**",
        "task_info.report.*.process_list.process.*.registry.**",
        "task_info.report.*.process_list.process.*.file.**",
        "task_info.report.*.process_list.process.*.service.**",
        "task_info.report.*.process_list.process.*.mutex.**",
        "task_info.report.*.process_tree.process",
        "task_info.report.*.evidence.file.entry",
    ]

    def listify_report_objects(self, report: dict) -> None:
        """Ensure that certain API endpoints always return lists of objects

        Some endpoints will return a single object when there is only one entry
        and a list of objects when there are multiple entries. To make report
        templating easier, we are going to enforce consistency in the report
        object for keys that we have identified in need of this treatment.

        Modifies the report in place.

        Args:
            report: The report object received from the WildFire API
        """
        for path in self._listify_wildfire_report_keys:
            path_keys = path.split('.')
            self._listify_path(report, path_keys)

    def _listify_path(self, pointer: dict, path_keys: list[str]) -> None:
        """Make recursive calls to process all of the path elements

        Args:
            pointer: Nested dict item that we're currently looking at
            path_keys: Remaining nested elements to be traversed
        """
        current_key = path_keys[0]
        if len(path_keys) == 1:
            if current_key == '**':
                if isinstance(pointer, dict):
                    for subkey in pointer.keys():
                        self._listify_path(pointer, [subkey])
            elif current_key in pointer and isinstance(pointer[current_key],
                                                       dict):
                pointer[current_key] = [pointer[current_key]]
        else:
            if current_key == '*':
                if isinstance(pointer, list):
                    for item in pointer:
                        self._listify_path(item, path_keys[1:])
            else:
                pointer = pointer.get(current_key)
                if pointer is not None:
                    self._listify_path(pointer, path_keys[1:])

    def get_verdict(self, data_type: str, data: str) -> Tuple[str, int]:
        """Get the WildFire verdict for the data, if possible

        Args:
            data_type: Data type
            data: Data value

        Returns:
            Verdict with string an integer values
        """
        request_url = self.api_root + "/get/verdict"
        if data_type in ['hash', 'file']:
            # Requires MD5 or SHA-256 hash value of the sample
            data = dict(apikey=self.api_key, hash=data)
        elif data_type == 'url':
            data = dict(apikey=self.api_key, url=data)
        else:
            self.error(
                f"Can't get verdict for unknown data type '{data_type}'")
        try:
            response = self.session.post(request_url, data=data)
            self._check_for_api_errors(response, "While getting verdict:")
        except requests.RequestException as e:
            self.error('Error while trying to get verdict: ' + str(e))

        verdict_int = int(xmltodict.parse(
            response.text)['wildfire']['get-verdict-info']['verdict'])
        verdict_str = WildFireAnalyzer._verdicts[verdict_int]
        return verdict_str, verdict_int

    def get_report(
            self,
            data_type: str,
            report_key: str,
            report_format='xml') -> dict:
        """Method for retrieving analysis reports

        Args:
            data_type: Data type, can be file, url or hash
            report_key: hash or URL
            report_format: either xml or pdf
        Returns:
            dict: Analysis results or None if there is no report available
        Raises:
             WildFireException: If an API error occurs
        """

        request_url = self.api_root + "/get/report"
        if data_type == "hash" or data_type == "file":
            request_data = dict(apikey=self.api_key, hash=report_key,
                                format=report_format)
        else:
            # Report format dosen't apply to URL reports
            report_format = None
            request_data = dict(apikey=self.api_key, url=report_key)

        try:
            response = self.session.post(request_url, data=request_data)
            self._check_for_api_errors(
                response,
                f"While getting report for {data_type=} with {report_key=}:")
        except requests.RequestException as e:
            self.error('Error while trying to get report: ' + str(e))

        if report_format is None:
            response = response.json()["result"]
            if response["analysis_time"] == "":
                response = None
            response["report"] = json.loads(response["report"])
        elif report_format == "pdf":
            response = response.content
        else:
            response = xmltodict.parse(response.text)
            response = response["wildfire"]

        if report_format == 'xml':
            self.listify_report_objects(response)
        return response

    def submit_file(self, file_path: str, filename="sample") -> dict:
        """Submits a file to WildFire for analysis
        Args:
            file_path: The file path of the object to send
            filename: An optional filename
        Returns:
            Tracking information for the sample we submitted
        Raises:
             WildFireException: If an API error occurs
        """
        url = self.api_root + "/submit/file"
        data = dict(apikey=self.api_key)
        files = dict(file=(filename, open(file_path, mode='rb')))
        try:
            response = self.session.post(url, data=data, files=files)
            self._check_for_api_errors(
                response,
                "While submitting file:")
        except requests.RequestException as e:
            self.error('Error while trying to submit file: ' + str(e))
        response_dict = xmltodict.parse(response.text)
        if 'wildfire' in response_dict:
            return response_dict['wildfire']['upload-file-info']
        else:
            self.error("Missing 'wildfire' key in response data: "
                       + str(response_dict))

    def submit_url(self, url: str) -> dict:
        """Submits a URL for analysis

        Args:
            url: A single URL
        Returns:
            Tracking information for the sample that was submitted
        Raises:
             WildFireException: If an API error occurs
        """

        request_url = self.api_root + "/submit/link"
        data = dict(apikey=self.api_key, link=url)
        try:
            response = self.session.post(request_url, data=data, files=data)
            self._check_for_api_errors(response, "While submitting URL:")
        except requests.RequestException as e:
            self.error('Error while trying to submit URL: ' + str(e))
        results = xmltodict.parse(response.text)[
            'wildfire']['submit-link-info']
        return results

    def summary(self, raw: dict):
        """Build taxonomies from the report data to give a summary"""
        taxonomies = []
        namespace = "WildFire"
        predicate = "Scan"
        wildfire_to_cortex_map = {
            "benign": "safe",
            "malware": "malicious",
            "greyware": "suspicious",
            "phishing": "malicious",
            "not found": "info",
        }
        if isinstance(raw['results'], str):
            value = raw['results']
            level = 'info'
        else:
            value = raw["results"].get("verdict", "not found")
            level = wildfire_to_cortex_map.get(value)

        taxonomies.append(
            self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):
        verdict = verdict_int = None
        if self.data_type == "file":
            filename = self.get_param('filename', 'sample')
            filepath = self.get_param('file', None, 'File is missing')

            with open(filepath, 'rb') as f:
                # Calculate SHA-256 hash locally so we can see if it's known
                data = self.get_file_hash(f)
            verdict, verdict_int = self.get_verdict('hash', data)
            if verdict_int < 0 and verdict != 'pending':
                result = self.submit_file(filepath, filename)
                verdict = verdict_int = None
                print(f"Result of submit_file: {result}")
                data = result['sha256']
        elif self.data_type == "url":
            data = self.get_param('data', None, 'Data is missing')
            # See if WildFire already knows about this data before submitting
            verdict, verdict_int = self.get_verdict(self.data_type, data)
            if verdict_int < 0 and verdict != 'pending':
                self.submit_url(data)
                verdict = verdict_int = None
        elif self.data_type == "hash":
            data = self.get_param('data', None, 'Data is missing')
            if len(data) == 40:
                self.error("WildFire dosen't support SHA-1 hashes")
        else:
            self.error(f"Unhandled data type {self.data_type}")

        tries = 0
        while verdict in [None, "pending"] and tries <= 20:
            time.sleep(self.polling_interval)
            verdict, verdict_int = self.get_verdict(self.data_type, data)
            tries += 1
        if verdict == "pending":
            self.error("WildFire API analysis timed out. Please try again")
        if verdict == "error":
            self.error("WildFire API returned error")

        print(f"Got {verdict=}, {verdict_int=} for {self.data_type} {data=}")
        report = self.get_report(self.data_type, data)
        if report is None:
            self.report({"results": "No report found"})
            return

        report["data_type"] = self.data_type
        report["verdict"] = verdict
        self.report({"results": report})


if __name__ == '__main__':
    WildFireAnalyzer().run()
