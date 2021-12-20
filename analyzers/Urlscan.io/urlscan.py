#!/usr/bin/env python3
import requests
import re
import json

regex_search_after = "\\d{13},[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"


class UrlscanException(Exception):
    pass


class Urlscan:
    def __init__(self, query="",api_key=""):
        assert len(query) > 0, "Query must be defined"
        self.query = query
        self.headers={"API-Key": api_key}

    def search(self, search_after=None):

        if re.match(regex_search_after, str(search_after)):
            payload = {"q": self.query,
                       "search_after": search_after
                       }
        else:
            payload = {"q": self.query}
        r = requests.get("https://urlscan.io/api/v1/search/", params=payload, verify=False, headers=self.headers)
        if r.status_code == 200:
            return r.json()
        else:
            raise UrlscanException("urlscan.io returns %s" % r.status_code)
