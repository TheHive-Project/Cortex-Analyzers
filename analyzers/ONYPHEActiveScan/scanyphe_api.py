#!/usr/bin/env python3
from requests.compat import urljoin
import requests
import json

class Scanyphe:
    """Wrapper around the Scanyphe REST API
    :param key: The Scanyphe API key
    :type key: str
    :param base_url: The Scanyphe API base URL
    :type base_url: str
    """

    def __init__(self, key: str, base_url: str):
        """Intializes the API object
        :param key: The Onyphe API key
        :type key: str
        """
        self.api_key = key
        self.base_url = base_url
        self._sessionPost = requests.Session()
        self._sessionGet = requests.Session()

    def scan(self, path: str, scan_params: dict={}):
        """Specialized wrapper around the requests module to request data from Onyphe
        :param path: The URL path after the onyphe FQDN
        :type path: str
        :param query_params: The dictionnary of query parameters that gets appended to the URL
        :type query_params: str
        """
        
        self._sessionPost.headers.update({'X-Api-Key': self.api_key})
        self._sessionPost.headers.update({'Content-Type': 'application/json'})
        url = urljoin(self.base_url, path)
        
        try:
            response = self._sessionPost.post(url, data=json.dumps(scan_params))
        except:
            raise APIGeneralError("Couldn't connect to Scanyphe API : {url}".format(url=url))

        if response.status_code == 429:
            raise APIRateLimiting(response.text)
        try:
            response_data = response.json()
        except:
            raise APIError("Couldn't parse response JSON from: {url}".format(url=url))

        if response_data["error"] > 0:
            raise APIError("API error {}: {}".format(
                str(response_data["error"]), response_data["text"]))

        return response_data

    def results(self, scanid: str):
        """Returns results from Scanyphe results API for a given scanid
        :param scanid: The ScanID to fetch results for
        :type scanid: str
        :param query_params: The dictionnary of query parameters that gets appended to the URL
        :type query_params: str
        """
        
        self._sessionGet.headers.update({'X-Api-Key': self.api_key})
        self._sessionGet.headers.update({'Content-Type': 'application/json'})
        url = urljoin(self.base_url, "ondemand/scope/result/{scanid}".format(scanid=str(scanid)))
        
        scan_params = {}
        scan_params["full"] = "true"
        
        try:
            response = self._sessionGet.get(url, data=json.dumps(scan_params))
        except:
            raise APIGeneralError("Couldn't connect to Scanyphe API : {url}".format(url=url))

        if response.status_code == 429:
            raise APIRateLimiting(response.text)
        try:
            response_data = response.json()
        except:
            raise APIError("Couldn't parse response JSON from: {url}".format(url=url))

        return response_data

    
class APIError(Exception):
    """This exception gets raised when the returned error code is non-zero positive"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class APIRateLimiting(Exception):
    """This exception gets raised when the 429 HTTP code is returned"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

class APIGeneralError(Exception):
    """This exception gets raised when there is a general API connection error"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value
    
class ScanypheError(Exception):
    """This exception gets raised when the returned error code is non-zero positive"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value
