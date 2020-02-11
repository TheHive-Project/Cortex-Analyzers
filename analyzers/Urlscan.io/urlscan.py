import requests
import json


class UrlscanException(Exception):
    pass


class Urlscan:
    def __init__(self, query=""):
        assert len(query) > 0, "Qeury must be defined"
        self.query = query

    def search(self):
        payload = {"q": self.query}
        r = requests.get("https://urlscan.io/api/v1/search/", params=payload)
        if r.status_code == 200:
            return r.json()
        else:
            raise UrlscanException("urlscan.io returns %s" % r.status_code)
