import json
import requests


class SecurityTrailsException(Exception):
    pass


class SecurityTrails():
    def __init__(self, api_key):
        self.base_url = "https://api.securitytrails.com/v1"
        self.api_key = api_key

        if self.api_key is None:
            raise SecurityTrailsException("No API key is present")

    def passive_dns(self, ipaddress):
        url = "{}/domains/list".format(self.base_url)
        payload = json.dumps({"filter": {"ipv4": ipaddress}})
        response = requests.request(
            "POST", url, data=payload, headers={"apikey": self.api_key})

        if response.status_code == 200:
            return response.json()
        else:
            raise SecurityTrailsException(
                "SecurityTrails returns {}".format(response.status_code))

    def whois(self, domain):
        url = "{}/domain/{}/whois".format(self.base_url, domain)
        response = requests.request(
            "GET", url, headers={"apikey": self.api_key})

        if response.status_code == 200:
            return response.json()
        else:
            raise SecurityTrailsException(
                "SecurityTrails returns {}".format(response.status_code))
