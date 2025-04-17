#!/usr/bin/env python3
# Author: THA-CERT // YNE

import requests
import json
from cortexutils.analyzer import Analyzer

class Watcher_CheckDomain(Analyzer):
    def __init__(self):
        super(Watcher_CheckDomain, self).__init__()

        # Load URL and API key from config
        base_url = self.get_param("config.watcher_url", None, "Watcher URL is missing.")
        self.watcher_url = f"{base_url.rstrip('/')}/api/site_monitoring/site/"
        self.watcher_api_key = self.get_param("config.watcher_api_key", None, "Watcher API key is missing.")

        # Set headers
        self.headers = {
            "Authorization": f"Token {self.watcher_api_key}",
            "Content-Type": "application/json"
        }

    def check_domain_status(self, domain):
        """Check if the domain is already being monitored in Watcher."""
        try:
            response = requests.get(
                self.watcher_url,
                headers=self.headers,
                verify=False
            )
            response.raise_for_status()
            sites = response.json()

            for site in sites:
                if site.get("domain_name") == domain:
                    return True, site.get("ticket_id")
            return False, None
        except requests.exceptions.RequestException as e:
            self.error(f"API request error while checking monitored domains: {str(e)}")
            return None, None

    def summary(self, raw):
        """Generate a summary for TheHive taxonomies."""
        taxonomies = []
        namespace = "Watcher"
        predicate = "Check"
        status = raw.get("status", "Not Monitored")

        level = "safe" if status == "Monitored" else "info"
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, status))

        return {"taxonomies": taxonomies}

    def run(self):
        try:
            data = self.get_data()

            if not data:
                self.error("No data received from Cortex. Cannot proceed.")
                return
            if isinstance(data, str):
                try:
                    if data.strip() and not data.startswith("{"):
                        data = json.loads(f'{{"data": "{data}"}}')
                except json.JSONDecodeError as e:
                    self.error(f"Invalid JSON received from Cortex. Input received: {data}. Error: {str(e)}")
                    return

            domain = data.get("data")

            if not domain or not isinstance(domain, str):
                self.error("Invalid input: Domain name is missing or not a string.")
                return

            is_monitored, ticket_id = self.check_domain_status(domain)

            if is_monitored:
                status = "Monitored"
                message = {
                    "status": status,
                    "Message": f"Domain '{domain}' is already monitored in Watcher.",
                    "ticket_id": ticket_id
                }
            else:
                status = "Not Monitored"
                message = {
                    "status": status,
                    "Message": f"Domain '{domain}' is not monitored in Watcher. You can add it using the Watcher responder."
                }

            self.report(message)
        except Exception as e:
            self.error(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    Watcher_CheckDomain().run()
