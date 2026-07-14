import requests
import json
import time


class UrlscanException(Exception):
    pass


class Urlscan:
    def __init__(self, query=""):
        assert len(query) > 0, "Qeury must be defined"
        self.query = query

    def search(self, api_key):
        payload = {"q": self.query}
        headers = {"api-key": api_key}
        r = requests.get("https://urlscan.io/api/v1/search/", params=payload, headers=headers)
        if r.status_code == 200:
            return r.json()
        else:
            raise UrlscanException("urlscan.io returns %s" % r.status_code)

    def scan(self, api_key, visibility="public"):
        headers = {
            "Content-Type": "application/json",
            "api-key": api_key,
        }
        url = self.query.strip('"')
        data = json.dumps({"url": url, "visibility": visibility})
        r = requests.post(
            "https://urlscan.io/api/v1/scan/", headers=headers, data=data
        )
        if r.status_code == 200:
            submission_url = r.json()["api"]

            tries = 0
            while tries <= 15:
                submission_req = requests.get(submission_url, headers=headers)
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
