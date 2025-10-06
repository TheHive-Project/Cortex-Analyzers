#!/usr/bin/env python3
from requests.compat import urljoin
import requests

class Onyphe:
    """Wrapper around the Onyphe REST API
    :param key: The Onyphe API key
    :type key: str
    """

    def __init__(self, key: str, base_url: str):
        """Intializes the API object
        :param key: The Onyphe API key
        :type key: str
        """
        self.api_key = key
        self.base_url = base_url
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

        try:
            response = self._session.get(url=url, data=query_params)
        except:
            raise APIGeneralError("Couldn't connect to ONYPHE API : {url}".format(url=url))

        if response.status_code == 429:
            raise APIRateLimiting(response.text)
        try:
            response_data = response.json()
        except:
            raise APIError("Couldn't parse response JSON from: {url}".format(url=url))

        if response_data["error"] > 0:
            raise APIGeneralError("Error {code} {text} : {url}".format(code=response_data["error"],text=response_data["text"],url=url))

        return response_data

    def summary(self, data: str, datatype: str):
        """Return a summary of all information we have for the given IPv{4,6} address. 
        """
        if datatype == 'ip':
            url_path = "summary/ip/{ip}".format(ip=data)
        elif datatype == 'domain':
            url_path = "summary/domain/{domain}".format(domain=data)
        elif datatype == 'fqdn':
            url_path = "summary/hostname/{hostname}".format(hostname=data)
        return self._request(path=url_path)

    
    def search_oql(self, oql: str):
        """Return data from specified category using Search API and the provided data as the OQL filter. 
        """
        url_path = "search/?q={oql}".format(oql=oql)
        return self._request(path=url_path)
    
    def search(self, data: str, datatype: str, category: str, filter: str):
        """Return data from specified category using Search API and the provided data as the OQL filter. 
        """
        if datatype == 'ip':
            url_path = "search/?q=category:{category}+ip:{ip}+{filter}".format(category=category,ip=data,filter=filter)
        elif datatype == 'domain':
            url_path = "search/?q=category:{category}+domain:{domain}+{filter}".format(category=category,domain=data,filter=filter)
        elif datatype == 'fqdn':
            url_path = "search/?q=category:{category}+hostname:{hostname}+{filter}".format(category=category,hostname=data,filter=filter)
        elif datatype == 'hash':
            url_path = "search/?q=category:{category}+fingerprint.sha256:{hash}+{filter}".format(category=category,hash=data,filter=filter)
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

class APIGeneralError(Exception):
    """This exception gets raised when there is a general API connection error"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

class OtherError(Exception):
    """This exception gets raised when we can't parse an other observable"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value