#!/usr/bin/env python3

import re
import time
from datetime import datetime, timedelta
from typing import Dict, Iterator, Pattern, Tuple, Union

import requests
from cortexutils.analyzer import Analyzer

AGENT_NAME_RE: Pattern = re.compile(r'"agentName":"([^"]+)"')
DATETIME_FORMAT: str = "%Y-%m-%dT%H:%M:%S.%fZ"
DEFAULT_CHECK_QUERY_SECONDS: int = 5
DEFAULT_EVENT_COUNT: int = 200
DEFAULT_HOURS_AGO: int = 2
NEXT_CURSOR_NONE: str = '"nextCursor":null,'
NEXT_CURSOR_RE: Pattern = re.compile(r'"nextCusrsor":"([^"]+)"')
S1_API_ENDPOINTS: Dict[str, str] = {
    "create-query-and-get-id": "/web/api/v2.1/dv/init-query",
    "check-query-status": "/web/api/v2.1/dv/query-status",
    "get-events": "/web/api/v2.1/dv/events",
}
SERVICES: Tuple[str] = ("dns-lookups",)
URL_RE: Pattern = re.compile(r"^[^:]+:\/{2}([\w\d\-\.]+).+$")
USER_AGENT: str = "Cortex/SentinelOne-Analyzer-v1.0"


class SentinelOne(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        # user configurable settings
        self.s1_console_url = self.get_param(
            "config.s1_console_url", None, "S1 console URL is missing!"
        )
        self.s1_api_key = self.get_param(
            "config.s1_api_key", None, "S1 API key is missing!"
        )
        self.s1_account_id = self.get_param(
            "config.s1_account_id", None, "Account ID is missing!"
        )

        self.service = self.get_param(
            "config.service", None, "IPinfo service is missing"
        )

        self.data = self.get_data()

        self.hours_ago = int(self.get_param("config.s1_hours_ago", DEFAULT_HOURS_AGO))
        if self.hours_ago < 1:
            self.error("hours_ago must be greater than 0")
            raise ValueError

        self.headers = {
            "Authorization": "ApiToken " + self.s1_api_key,
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if self.service not in SERVICES:
            self.error("bad service")

        self.s1_check_query_seconds = DEFAULT_CHECK_QUERY_SECONDS
        self.s1_query_item_count = DEFAULT_EVENT_COUNT
        self.s1_api_endpoints = S1_API_ENDPOINTS
        self.s1_datetime_format = DATETIME_FORMAT

    def _check_query_status(self, query_id: str) -> Tuple[bool, bool]:
        response = requests.get(
            self.s1_console_url + self.s1_api_endpoints["check-query-status"],
            headers=self.headers,
            params={"queryId": query_id},
        )
        """Check Query Status
        Returns tuple of done, error
        """
        if response.status_code == requests.codes.ok:
            data = response.json()
            if data["data"]["responseState"] == "RUNNING":
                return False, False
            elif data["data"]["responseState"] == "FINISHED":
                return True, False
            else:
                self.error(data["data"]["responseState"])
                return False, True
        else:
            self.error(self.errors_to_string(response))
            return False, True

    def _create_query_and_get_id(self, query: str) -> Union[str, None]:
        """Create Query and Get ID
        """
        to_date = datetime.utcnow()
        response = requests.post(
            self.s1_console_url + self.s1_api_endpoints["create-query-and-get-id"],
            headers=self.headers,
            json={
                "fromDate": self.get_from_date(to_date).strftime(
                    self.s1_datetime_format
                ),
                "toDate": to_date.strftime(self.s1_datetime_format),
                "query": query,
                "accountIds": [self.s1_account_id,],
                "queryType": ["events",],
            },
        )
        if response.status_code == requests.codes.ok:
            data = response.json()
            return data["data"]["queryId"]
        else:
            self.error(self.errors_to_string(response))
        return None

    def agent_name_generator(
        self, query_id: str, next_cursor: str = None
    ) -> Iterator[str]:
        """Agent Name Generator
        Response may be massive, this will make multiple calls of 200 records at a time.
        Each time looking for "AgentName" values as well as the "NextCursor".  This
        would be simple if SentinelOne's API for Deep Visibility let you either GROUP
        BY or pull a specified list of fields.
        """

        done, errored = False, False
        params = {"queryId": query_id, "limit": self.s1_query_item_count}
        while not (done or errored):
            if next_cursor:
                params["nextCursor"] = next_cursor

            response = requests.get(
                self.s1_console_url + self.s1_api_endpoints["get-events"],
                headers=self.headers,
                params=params,
            )

            if response.status_code != requests.codes.ok:
                errored = True
                self.error(self.errors_to_string(response))
            else:
                data = response.text

                # if nextCursor is null, this is the end of the data
                if NEXT_CURSOR_NONE in data:
                    done = True
                else:
                    # get the next_cursor
                    match_obj = NEXT_CURSOR_RE.search(data)
                    if match_obj is not None:
                        next_cursor = match_obj.group(1)
                    else:
                        errored = True

                # find all agent names
                matches = AGENT_NAME_RE.findall(data)
                if matches is not None:
                    return iter(matches)

    def artifacts(self, raw):
        if self.service == "dns-lookups":
            return [
                {"dataType": "host", "data": agent_name}
                for agent_name in raw.get("agent_names", [])
            ]
        return []

    def errors_to_string(self, response: requests.Response) -> str:
        """Errors to String
        Pull error(s) from JSON response if exists in response.  Return them as a single string.
        """
        try:
            data = response.json()
            return "\n".join(
                [f"{e['title']}: {e['detail']} ({e['code']})" for e in data["errors"]]
            )
        except ValueError:
            return f"Recived {response.status_code} from SentinelOne."

    def get_from_date(self, to_date: datetime) -> datetime:
        """Get FromDate
        Calculate FromDate from to_date - hours_ago
        """
        return to_date - timedelta(hours=self.hours_ago)

    def run(self):
        if self.service == "dns-lookups":
            if self.data_type not in ("domain", "fqdn", "url"):
                self.not_supported()

            data = self.get_data()
            if self.data_type == "url":
                match_obj = URL_RE.match(data)
                if match_obj is not None:
                    data = match_obj.group(1)
                else:
                    self.not_supported()

            # create query and get query ID
            query_id = self._create_query_and_get_id(
                f'EventType = "DNS Resolved" AND DNSRequest contains "{data}"'
            )
            if query_id is not None:

                # wait for query to finish
                done, errored = False, False
                while not (done or errored):
                    time.sleep(self.s1_check_query_seconds)
                    done, errored = self._check_query_status(query_id)

                if not errored:
                    agent_names = set()
                    for agent_name in self.agent_name_generator(query_id):
                        agent_names.add(agent_name)
                    if agent_names:
                        data = list(agent_names)
                        data.sort()
                    else:
                        data = []
                    self.report({"agent_names": data})

    def summary(self, raw):
        if self.service == "dns-lookups":
            count = len(raw.get("agent_names", []))
            if count == 0:
                level = "safe"
            else:
                level = "suspicious"
            return {
                "taxonomies": [self.build_taxonomy(level, "S1", "host_count", count)]
            }
        return {}


if __name__ == "__main__":
    SentinelOne().run()
