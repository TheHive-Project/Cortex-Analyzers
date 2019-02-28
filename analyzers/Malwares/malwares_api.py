#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import requests


class Api():

    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base = 'https://public.api.malwares.com/v3/'
        self.version = 2
        if api_key is None:
            raise ApiError("You must supply a valid Malwares API key.")

    def scan_file(self, this_file, this_filename):
        """ Submit a file to be scanned by Malwares

        :param this_file: File to be scanned (200MB file size limit)
        :param this_filename: Filename for scanned file
        :return: JSON response that contains scan_id and permalink.
        """
        params = {
            'api_key': self.api_key,
            'filename': this_filename
        }
        try:
            files = {'file': (this_file.name, open(this_file.name, 'rb'), 'application/octet-stream')}
        except TypeError as e:
            return dict(error=e.message)

        try:
            response = requests.post(self.base + 'file/upload', files=files, data=params)
        except requests.RequestException as e:
            return dict(error=e.message)

        return _return_response_and_status_code(response)

    def get_file_report(self, this_hash):
        """ Get the scan results for a file.

        :param this_hash: The md5/sha1/sha256/scan_ids hash of the file whose dynamic behavioural report you want to
                            retrieve or scan_ids from a previous call to scan_file.
        :return:
        """
        params = {'api_key': self.api_key, 'hash': this_hash}

        try:
            response_info = requests.get(self.base + 'file/mwsinfo', params=params)
            response_additional = requests.get(self.base + 'file/addinfo', params=params)
        except requests.RequestException as e:
            return dict(error=e.message)

        ri = _return_response_and_status_code(response_info)
        ra = _return_response_and_status_code(response_additional)

        if ri['response_code'] == '1' and ra['response_code'] == '1':  # both ok
            both = ri['results'].copy()
            both.update(ra['results'])
            response = dict(results=both, response_code=1)
        elif ri['response_code'] == '1' and ra['response_code'] == '0':  # advance non exists but standard ok
            response = ri
        elif ri['response_code'] == '2':  # main is still loading
            response = dict(results={}, response_code=2)
        else:  # error generic
            response = ri
        return response

    def scan_url(self, this_url):
        """ Submit a URL to be scanned by Malwares.

        :param this_url: The URL that should be scanned. 
        :return: JSON response that contains scan_id and permalink.
        """
        params = {'api_key': self.api_key, 'url': this_url}

        try:
            response = requests.post(self.base + 'url/request', data=params)
        except requests.RequestException as e:
            return dict(error=e.message)

        return _return_response_and_status_code(response)

    def get_url_report(self, this_url):
        """ Get the scan results for a URL.

        :param this_url: a URL will retrieve the most recent report on the given URL. 
        :return: JSON response
        """
        params = {'api_key': self.api_key, 'url': this_url}

        try:
            response = requests.post(self.base + 'url/info', data=params)
        except requests.RequestException as e:
            return dict(error=e.message)

        return _return_response_and_status_code(response)

    def get_ip_report(self, this_ip):
        """ Get IP address reports.

        :param this_ip: a valid IPv4 address in dotted quad notation, for the time being only IPv4 addresses are
                        supported.
        :return: JSON response
        """
        params = {'api_key': self.api_key, 'ip': this_ip}

        try:
            response = requests.get(self.base + 'ip/info', params=params)
        except requests.RequestException as e:
            return dict(error=e.message)

        return _return_response_and_status_code(response)

    def get_domain_report(self, this_domain):
        """ Get information about a given domain.

        :param this_domain: a domain name.
        :return: JSON response
        """
        params = {'api_key': self.api_key, 'hostname': this_domain}

        try:
            response = requests.get(self.base + 'hostname/info', params=params)
        except requests.RequestException as e:
            return dict(error=e.message)

        return _return_response_and_status_code(response)


class ApiError(Exception):
    pass


def _return_response_and_status_code(response):
    """ Output the requests response JSON and status code

    :rtype : dict
    :param response: requests response object
    :return: dict containing the JSON response and/or the status code with error string.
    """

    result_codes = {
        "-11": "No matching data to API Key API Key error",
        "-12": "No authority to use No authority to use",
        "-13": "Expired API Key API Key expired",
        "-14": "Over the daily request limit Request limit per daily exceeded",
        "-15": "Over the hourly request limit Request limit per hour exceeded",
        "-1": "Invalid Parameters / Invalid Request",
        "-25": "File Upload Quota Limit Error in file size to upload",
        "-2": "Invalid URL Error in URL type",
        "-31": "Invalid type of hash error in Hash type",
        "-400": "No file attached No file attached",
        "-404": "No result No result",
        "-415": "Ectype of upload form is not multipart/form-data Error in upload form type",
        "-41": "Invalid type of url Error in URL type",
        "-500": "Internal Server Error System error",
        "-51": "Invalid type of ip Error in IP type",
        "-61": "Invalid type of hostname Error in Hostname type",
        "0": "Data is not exist No information found in DB.",
        "1": "Data exists / Analysis request succeeded /Successful upload (new)",
        "2": "Analysis in progress / Successful upload (duplicated)",
        "-999": "Error"

    }

    results = response.json()

    result_code = str(response.json().get('result_code', '-999'))
    result_message = result_codes[result_code]
    return dict(results=results, response_code=result_code, result_message=result_message)
