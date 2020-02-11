#!/usr/bin/env python3

import requests


class EmailRepException(Exception):
    pass


class EmailRep():
    def __init__(self):
        self.base_url = "https://emailrep.io"

    def get(self, email_address):
        url = "{}/{}".format(self.base_url, email_address)
        json = self._request(url)
        json["mail"] = email_address
        return json

    def _request(self, url):
        res = requests.request("GET", url)

        if res.status_code != 200:
            raise EmailRepException(
                "emailrep returns {}".format(res.status_code))

        json = res.json()
        status = json.get("status")
        if status == "fail":
            reason = json.get("reason")
            raise EmailRepException(reason)

        return json
