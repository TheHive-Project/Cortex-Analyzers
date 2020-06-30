#!/usr/bin/env python3
from requests.compat import urljoin
import requests


class Onyphe:
    """Wrapper around the Onyphe REST API
    :param key: The Onyphe API key
    :type key: str
    """

    def __init__(self, key: str):
        """Intializes the API object
        :param key: The Onyphe API key
        :type key: str
        """
        self.api_key = key
        self.base_url = "https://www.onyphe.io/"
        self._session = requests.Session()

    def _request(self, path: str, query_params: dict={}):
        """Specialized wrapper around the requests module to request data from Onyphe
        :param path: The URL path after the onyphe FQDN
        :type path: str
        :param query_params: The dictionnary of query parameters that gets appended to the URL
        :type query_params: str
        """
        query_params["apikey"] = self.api_key
        url = urljoin(self.base_url, path)
        response = self._session.get(url=url, data=query_params)

        if response.status_code == 429:
            raise APIRateLimiting(response.text)
        try:
            response_data = response.json()
        except:
            raise APIError("Couldn't parse response JSON")

        if response_data["error"] > 0:
            raise APIError("got error {}: {}".format(
                response_data["error"], response_data["message"]))

        return response_data

    def summary(self, data: str, datatype: str):
        """Return a summary of all information we have for the given IPv{4,6} address. 
        """
        if datatype == 'ip':
            url_path = "/api/v2/summary/ip/{ip}".format(ip=data)
        elif datatype == 'domain':
            url_path = "/api/v2/summary/domain/{domain}".format(domain=data)        
        elif datatype == 'hostname':
            url_path = "/api/v2/summary/hostname/{hostname}".format(hostname=data)                 
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
