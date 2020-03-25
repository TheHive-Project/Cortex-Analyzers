import requests
import json
import time


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

    def scan(self, api_key):
        headers = {
            "Content-Type": "application/json",
            "API-Key": api_key,
        }
        data = '{"url": %s, "public": "on"}' % self.query
        r = requests.post(
            "https://urlscan.io/api/v1/scan/", headers=headers, data=data, verify=False
        )
        if r.status_code == 200:
            submission_url = r.json()["api"]

            finished = False
            tries = 0
            while tries <= 15:        
                submission_req = requests.get(submission_url)
                if submission_req.status_code == 200:
                    return submission_req.json()
                tries += 1
                time.sleep(20)

            raise UrlscanException(
                "urlscan.io returns {0} and data was {1} on url {2}".format(
                    submission_req.status_code, data, submission_url
                )
            )

        else:
            raise UrlscanException(
                "urlscan.io returns {0} and data was {1}".format(r.status_code, data)
            )
