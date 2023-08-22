#!/usr/bin/env python3

import requests


class IPinfoException(Exception):
    pass


class IPinfo():
    def __init__(self, api_key):
        self.base_url = "https://ipinfo.io"
        self.api_key = api_key

        if self.api_key is None:
            raise IPinfoException("No API key is present")

        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": "Bearer {}".format(self.api_key)})

    def details(self, ip_address):
        url = "{}/{}".format(self.base_url, ip_address)
        return self._request(url)

    def hosted_domains(self, ip_address):
        url = "{}/domains/{}".format(self.base_url, ip_address)
        return self._request(url)

    def _request(self, url):
        res = self.session.request("GET", url)

        if res.status_code != 200:
            raise IPinfoException("IPinfo returns {}".format(res.status_code))

        if res.text == "":
            return {}

        return res.json()
