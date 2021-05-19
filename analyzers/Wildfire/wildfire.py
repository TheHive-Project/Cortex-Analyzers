#!/usr/bin/env python3
# encoding: utf-8

import json
import time
import xmltodict
from cortexutils.analyzer import Analyzer
from requests import Session


class WildFireException(RuntimeError):
    """This exception is raised when an API error occurs"""
    pass


class WildfireAnalyzer(Analyzer):
    @staticmethod
    def _raise_errors(response, *args, **kwargs):
        """Requests response processing hook"""
        if response.headers['content-type'].lower() == "text/xml" and len(
                response.text) > 0:
            results = xmltodict.parse(response.text)
            if "error" in results.keys():
                raise WildFireException(results["error"]["error-message"])
        if response.status_code != 200:
            raise WildFireException(WildfireAnalyzer._errors[response.status_code])

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
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.api_key = self.get_param('config.key', None, "Missing Wildfire API Key")
        self.host = "wildfire.paloaltonetworks.com"
        self.api_root = "https://{0}{1}".format(self.host, "/publicapi")
        self.session = Session()
        self.session.proxies = proxies
        self.session.verify = verify
        # self.session.hooks = dict(response=WildfireAnalyzer._raise_errors)
        # self.session.headers.update({"User-Agent": "pyldfire/{0}".format(
        #    __version__)})

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
        -102: "not found"
    }

    def get_veredict(self, data_type, data):
        request_url = self.api_root + "/get/verdict"
        if data_type == "hash" or data_type == "file":
            data = dict(apikey=self.api_key, hash=data)
        else:
            data = dict(apikey=self.api_key, url=data)
        response = self.session.post(request_url, data=data)
        verdict = int(xmltodict.parse(
            response.text)['wildfire']['get-verdict-info']['verdict'])
        results = WildfireAnalyzer._verdicts[verdict]
        return results

    def get_report(self, data_type, data, report_format='xml'):
        """Method for retrieving analysis reports
        Args:
            data_type (str):  Data type, can be url or hash
            data (str):  A hash of a sample
            report_format (str): either xml or pdf
        Returns:
            dict: Analysis results or None if there is no report available
        Raises:
             WildFireException: If an API error occurs
        """

        request_url = self.api_root + "/get/report"
        if data_type == "hash" or data_type == "file":
            data = dict(apikey=self.api_key, hash=data, format=report_format)
        else:
            # Report format dosen't apply to URL reports
            report_format = None
            data = dict(apikey=self.api_key, url=data)
        response = self.session.post(request_url, data=data)

        if report_format is None:
            response = response.json()["result"]
            if response["analysis_time"] == "":
                response = None
            response["report"] = json.loads(response["report"])
        elif report_format == "pdf":
            response = response.content
        else:
            response = xmltodict.parse(response.text)
            error = response.get("error", None)
            if error and error.get("error-message", None) == "'Report not found'":
                return None
            response = json.loads(json.dumps(response["wildfire"]))

        return response

    def submit_file(self, file_path, filename="sample"):
        """Submits a file to WildFire for analysis
        Args:
            file_path (file): The file path of the object to send
            filename (str): An optional filename
        Returns:
            dict: Analysis results
        Raises:
             WildFireException: If an API error occurs
        """
        url = self.api_root + "/submit/file"
        data = dict(apikey=self.api_key)
        files = dict(file=(filename, open(file_path, mode='rb')))
        response = self.session.post(url, data=data, files=files)

        return xmltodict.parse(response.text)['wildfire']['upload-file-info']

    def submit_url(self, url):
        """
        Submits a URL for analysis
        Args:
            url (str): A single URL
        Returns:
            dict: If a single URL is passed, a dictionary of analysis results
        Raises:
             WildFireException: If an API error occurs
        """

        request_url = self.api_root + "/submit/link"
        data = dict(apikey=self.api_key, link=url)
        response = self.session.post(request_url, data=data, files=data)
        results = xmltodict.parse(response.text)['wildfire']['submit-link-info']

        return results

    def summary(self, raw):
        taxonomies = []
        namespace = "Wildfire"
        predicate = "GetReport"

        if self.service == "scan":
            predicate = "Scan"

        verdict = raw["results"].get("verdict", "not found")
        verdicts = {
            "benign": "safe",
            "malware": "malicious",
            "greyware": "suspicious",
            "phishing": "malicious",
            "not found": "info",
        }
        level = verdicts.get(verdict)

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, verdict))

        return {"taxonomies": taxonomies}

    def run(self):
        # If service is scan we send the ioc to scan
        if self.service == "scan":
            if self.data_type == "file":
                filename = self.get_param('filename', 'sample')
                filepath = self.get_param('file', None, 'File is missing')
                result = self.submit_file(filepath, filename)
                data = result["sha256"]
            elif self.data_type == "url":
                url = self.get_param('data', None, 'Data is missing')
                self.submit_url(url)
                data = url
            else:
                self.error("Data type has to be URL or File")
                return

        elif self.service == "get":
            data = self.get_param('data', None, 'Data is missing')
        else:
            self.error("Service doesn't exists")
            return

        data_type = self.data_type
        if data_type == "hash" and len(data) == 40:
            self.error("Wildfire dosen't support SHA-1 hashes")
        verdict = self.get_veredict(data_type, data)
        tries = 0
        while verdict == "pending" and tries <= 20:
            time.sleep(self.polling_interval)
            verdict = self.get_veredict(data_type, data)
            tries += 1
        if verdict == "pending":
            self.error("Wildfire API analysis timed out. Please try again")
        elif verdict == "error":
            self.error("Wildfire API returned error")
        else:
            report = self.get_report(data_type, data)
            if report is None:
                self.report({"results": "No report found"})
                return
            report["data_type"] = data_type
            report["verdict"] = verdict
            self.report({"results": report})
        return


if __name__ == '__main__':
    WildfireAnalyzer().run()
