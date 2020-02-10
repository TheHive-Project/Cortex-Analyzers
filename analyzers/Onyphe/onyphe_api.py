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
        self.base_url = "https://www.onyphe.io"
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

    def _request_without_api(self, path: str, query_params: dict={}):
        """Specialized wrapper around the requests module to request data from Onyphe without the api_key(geolocate and myip)
        :param path: The URL path after the onyphe FQDN
        :type path: str
        :param query_params: The dictionnary of query parameters that gets appended to the URL
        :type query_params: str
        """
        url = urljoin(self.base_url, path)
        response = self._session.get(url=url, data=query_params)

        if response.status_code == 429:
            raise APIRateLimiting(response.text)
        try:
            response_data = response.json()
        except Exception:
            raise APIError("Couldn't parse response JSON")

        if response_data["error"] > 0:
            raise APIError("got error {}: {}".format(
                response_data["error"], response_data["message"]))

        return response_data

    def myip(self):
        """This method is open to use. There is need for an API key.
        """
        url_path = "/api/myip"
        return self._request_without_api(path=url_path)

    def geolocate(self, ip: str):
        """Return geolocate information from ip address (Geolocate doesn't need apikey !!)
        """
        url_path = "/api/geoloc/{ip}".format(ip=ip)
        return self._request_without_api(path=url_path)

    def ip(self, ip: str):
        """Return a summary of all information we have for the given IPv{4,6} address. History of changes will not be shown, only latest results.
        """
        url_path = "/api/ip/{ip}".format(ip=ip)
        return self._request(path=url_path)

    def inetnum(self, ip: str):
        """Return inetnum information we have for the given IPv{4,6} address with history of changes. Multiple subnets may match because of delegation mechanisms. We return all of them
        """
        url_path = "/api/inetnum/{ip}".format(ip=ip)
        return self._request(path=url_path)

    def threatlist(self, ip: str):
        """Return threatlist information we have for the given IPv{4,6} address with history of changes
        """
        url_path = "/api/threatlist/{ip}".format(ip=ip)
        return self._request(path=url_path)

    def pastries(self, ip: str):
        """Return pastries information we have for the given IPv{4,6} address with history of changes.
        """
        url_path = "/api/pastries/{ip}".format(ip=ip)
        return self._request(path=url_path)

    def synscan(self, ip: str):
        """Return synscan information we have for the given IPv{4,6} address with history of changes. Multiple synscan entries may match. We return all of them.
        """
        url_path = "/api/synscan/{ip}".format(ip=ip)
        return self._request(path=url_path)

    def datascan(self, search: str):
        """Return datascan information we have for the given IPv{4,6} address or string with history of changes
        """
        url_path = "/api/datascan/{search}".format(search=search)
        return self._request(path=url_path)

    def reverse(self, search: str):
        """Return reverse DNS lookup information we have for the given IPv{4,6} address with history of changes. Multiple reverse DNS entries may match. We return all of them.
        """
        url_path = "/api/reverse/{search}".format(search=search)
        return self._request(path=url_path)

    def forward(self, search: str):
        """Return forward DNS lookup information we have for the given IPv{4,6} address with history of changes. Multiple forward DNS entries may match. We return all of them.
        """
        url_path = "/api/forward/{search}".format(search=search)
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
