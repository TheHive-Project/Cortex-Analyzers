#!/usr/bin/env python3
import requests
import time


class UrlDNAException(Exception):
    """Custom exception for errors related to UrlDNA operations."""
    pass


class UrlDNA:
    """A client for interacting with the UrlDNA API."""

    BASE_URL = "https://api.urldna.io"

    def __init__(self, query, data_type="url"):
        """
        Initializes the UrlDNA instance with a query and data type.

        :param query: The query to be processed (e.g., URL, domain, or IP).
        :param data_type: Type of the query ('url', 'domain', or 'ip').
        :raises ValueError: If the query is empty or the data type is unsupported.
        """
        if not query:
            raise ValueError("Query must be defined.")
        if data_type not in ["url", "domain", "ip"]:
            raise ValueError(f"Unsupported data type: {data_type}")

        self.query = query
        self.data_type = data_type
        self.session = None

    def search(self, api_key):
        """
        Performs a search query on the UrlDNA API.

        :param api_key: API key for authentication.
        :return: A dictionary containing the search results.
        """
        self._init_session(api_key)
        uri = "/search"
        data = {"query": self._build_query()}
        response = self.session.post(f"{self.BASE_URL}{uri}", json=data)
        response.raise_for_status()
        return response.json()

    def new_scan(self, api_key, device=None, user_agent=None, viewport_width=None, viewport_height=None,
                 waiting_time=None, private_scan=False, scanned_from="DEFAULT"):
        """
        Initiates a new scan and polls for results until completion.

        :param api_key: API key for authentication.
        :param device: The device type ('MOBILE' or 'DESKTOP'). Defaults to 'DESKTOP'.
        :param user_agent: The user agent string for the scan. Defaults to a common desktop user agent.
        :param viewport_width: Width of the viewport. Defaults to 1920.
        :param viewport_height: Height of the viewport. Defaults to 1080.
        :param waiting_time: Time to wait before starting the scan. Defaults to 5 seconds.
        :param private_scan: Whether the scan is private. Defaults to False.
        :param scanned_from: The origin of the scan. Defaults to 'DEFAULT'.
        :return: A dictionary containing the scan results.
        :raises UrlDNAException: If the scan fails or polling times out.
        """
        self._init_session(api_key)
        try:
            scan_id = self._initiate_scan(device, user_agent, viewport_width, viewport_height,
                                          waiting_time, private_scan, scanned_from)
            return self._poll_for_result(scan_id)
        except requests.RequestException as exc:
            raise UrlDNAException(f"HTTP error during scan: {exc}")
        except Exception as exc:
            raise UrlDNAException(f"Error during scan: {exc}")

    def _build_query(self):
        """
        Builds the query string based on the data type.

        :return: A formatted query string.
        """
        if self.data_type == "url":
            return f"submitted_url = {self.query}"
        if self.data_type == "domain":
            return f"domain = {self.query}"
        if self.data_type == "ip":
            return f"ip = {self.query}"
        return self.query

    def _initiate_scan(self, device, user_agent, viewport_width, viewport_height, waiting_time,
                       private_scan, scanned_from):
        """
        Sends a request to initiate a new scan.

        :param device: The device type for the scan.
        :param user_agent: The user agent string for the scan.
        :param viewport_width: The viewport width for the scan.
        :param viewport_height: The viewport height for the scan.
        :param waiting_time: Time to wait before starting the scan.
        :param private_scan: Whether the scan is private.
        :param scanned_from: The origin of the scan.
        :return: The scan ID for the initiated scan.
        :raises UrlDNAException: If the scan ID is not returned.
        """
        data = {
            "submitted_url": self.query,
            "device": device or "DESKTOP",
            "user_agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0;Win64;x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"),
            "width": viewport_width or 1920,
            "height": viewport_height or 1080,
            "waiting_time": waiting_time or 5,
            "private_scan": private_scan if private_scan is not None else False,
        }

        # Only include scanned_from if explicitly set (requires Premium API plan)
        if scanned_from:
            data["scanned_from"] = scanned_from

        response = self.session.post(f"{self.BASE_URL}/scan", json=data)
        response.raise_for_status()
        scan_id = response.json().get("id")
        if not scan_id:
            raise UrlDNAException("Scan ID not returned.")
        return scan_id

    def _poll_for_result(self, scan_id):
        """
        Polls the API for the scan results until they are available.

        :param scan_id: The scan ID to poll.
        :return: A dictionary containing the scan results.
        :raises UrlDNAException: If the polling times out.
        """
        uri = f"/scan/{scan_id}"
        max_attempts = 10
        poll_interval = 10

        for attempt in range(max_attempts):
            if attempt > 0:
                time.sleep(poll_interval)
            response = self.session.get(f"{self.BASE_URL}{uri}")
            response.raise_for_status()
            result = response.json()

            status = result.get("scan", {}).get("status")
            if status not in ["RUNNING", "PENDING"]:
                return result

        raise UrlDNAException("Polling timed out before the scan completed.")

    def _init_session(self, api_key):
        """
        Initializes an HTTP session with the API key for authentication.

        :param api_key: The API key for authentication.
        """
        if not self.session:
            self.session = requests.Session()
            self.session.headers.update({
                "Content-Type": "application/json",
                "User-Agent": "strangebee-thehive",
                "Authorization": api_key
            })
