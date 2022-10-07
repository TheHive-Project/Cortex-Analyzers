#!/usr/bin/env python3
from requests.compat import urljoin
import requests


class Crowdsec:
    """Wrapper around the Crowdsec REST API
    :param key: The Crowdsec API key
    :type key: str
    """

    def __init__(self, key: str):
        """Intializes the API object
        :param key: The Crowdsec API key
        :type key: str
        """
        self.api_key = key
        self.base_url = "https://cti.api.crowdsec.net"

    def _request(self, path: str):
        """Specialized wrapper around the requests module to request data from Crowdsec
        :param path: The URL path after the Crowdsec FQDN
        :type path: str
        """
        headers = {
                "x-api-key": self.api_key ,
                "accept": "application/json"
                }
        url = urljoin(self.base_url, path)
        response = requests.get(url, headers=headers)

        if response.status_code == 429:
            raise APIRateLimiting(response.text)
        try:
            response_data = response.json()
        except:
            raise APIError("Couldn't parse response JSON")

        return response_data

    def summary(self, data: str, datatype: str):
        """Return a summary of all information we have for the given IPv{4,6} address. 
        """
        if datatype == 'ip':
            url_path = "/v2/smoke/{ip}".format(ip=data)
        return self._request(path=url_path)


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

