#!/usr/bin/env python3

import re
from cortexutils.responder import Responder
import requests


class SentinelOne(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.s1_console_url = self.get_param(
            "config.s1_console_url", None, "S1 console URL is missing!"
        )
        self.s1_api_key = self.get_param(
            "config.s1_api_key", None, "S1 API key is missing!"
        )
        self.s1_account_id = self.get_param(
            "config.s1_account_id", None, "Account ID is missing!"
        )
        self.s1_blacklist_ostype = self.get_param("s1_blacklist_ostype", "windows")
        self.s1_blacklist_type = "black_hash"

        self.observable = self.get_param("data.data", None, "Data is empty!")
        self.observable_type = self.get_param(
            "data.dataType", None, "Data type is empty!"
        )

        self.headers = {
            "Authorization": f"ApiToken {self.s1_api_key}",
            "User-Agent": "Cortex/SentinelOne-Responder",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        self.service = self.get_param("config.service", None, "Service Missing!")
        self.sha1_re = re.compile(r"^[A-Za-z0-9]{40}$")
        self.s1_blacklist_api_endpoint = "/web/api/v2.1/restrictions"

    def run(self):
        Responder.run(self)

        if self.service == "s1_blacklist":
            if self.s1_blacklist_ostype not in (
                "linux",
                "macos",
                "windows",
                "windows_legacy",
            ):
                self.error(f"{self.s1_blacklist_ostype} is not a valid OS Type")
                return

            if self.observable_type != "hash":
                self.error(f"{self.observable} is not a hash")
                return

            else:
                if self.sha1_re.match(self.observable) is None:
                    self.error(f"{self.observable} is not a valid SHA1 hash")
                    return

            response = requests.post(
                f"{self.s1_console_url}{self.s1_blacklist_api_endpoint}",
                headers=self.headers,
                json={
                    "data": {
                        "type": self.s1_blacklist_type,
                        "value": self.observable,
                        "osType": self.s1_blacklist_ostype,
                    },
                    "filter": {"accountIds": [self.s1_account_id,]},
                },
            )

            if response.status_code == requests.codes.ok:
                self.report({"message": "Blacklisted in SentinelOne."})

            else:
                self.error(
                    f"Error, unable to complete action, recieved {response.status_code} status code from SentinelOne API!"
                )

    def operations(self, raw):
        return [self.build_operation("AddTagToArtifact", tag="SentinelOne:blocked")]


if __name__ == "__main__":
    SentinelOne().run()
