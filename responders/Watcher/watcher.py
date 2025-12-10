#!/usr/bin/env python3
# Author: THA-CERT // YNE

import requests
import json
from cortexutils.responder import Responder

class Watcher_MonitorManager(Responder):
    def __init__(self):
        super(Watcher_MonitorManager, self).__init__()

        # Load URL and API key from config
        base_url = self.get_param("config.watcher_url", None, "Watcher URL is missing.")
        self.watcher_url = f"{base_url.rstrip('/')}/api/site_monitoring/site/"
        self.watcher_api_key = self.get_param("config.watcher_api_key", None, "Watcher API key is missing.")
        self.the_hive_custom_field = self.get_param("config.the_hive_custom_field", "watcher-id", "Custom Field is missing.")
        self.service = self.get_param("config.service", None, "Service parameter is missing.")

        # Set headers
        self.headers = {
            "Authorization": f"Token {self.watcher_api_key}",
            "Content-Type": "application/json"
        }

    def validate_artifact(self, data):
        """Validate if the artifact type is supported (only 'domain' is accepted)."""
        domain = data.get("data", None)
        artifact_type = data.get("dataType", None)

        if artifact_type != "domain":
            return False, None

        return True, domain

    def extract_source_ref(self, data):
        """Extract sourceRef (watcher-id) from the provided data, if available."""
        container = data.get("alert") or data.get("case", {})
        custom_fields = container.get("customFieldValues", {})
        return custom_fields.get(self.the_hive_custom_field, None)

    def is_domain_already_monitored(self, domain):
        """Check if the domain is already being monitored."""
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
                    self.error(f"Domain '{domain}' already exists in Watcher and is being monitored.")
                    return True
            return False
        except requests.exceptions.RequestException as e:
            self.error(f"API request error while checking monitored domains: {str(e)}")
            return False

    def add_monitor(self, domain, source_ref):
        """Add a domain to monitoring."""
        if self.is_domain_already_monitored(domain):
            return

        payload = {
            "action": "add",
            "domain_name": domain,
            "ticket_id": source_ref
        }

        try:
            response = requests.post(
                self.watcher_url,
                headers=self.headers,
                json=payload,
                verify=False,
            )
            response.raise_for_status()

            response_data = response.json() if response.content else {}

            return {
                "Message": f"Domain '{domain}' successfully added to monitoring with {self.the_hive_custom_field}: '{source_ref}'.",
                "WatcherResponse": response_data
            }
        except requests.exceptions.RequestException as e:
            self.error(f"Failed to add domain '{domain}' to monitoring: {str(e)}")

    def get_site_id(self, domain):
        """Get the site ID associated with a given domain."""
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
                    return site.get("id")

            self.error(f"Domain '{domain}' not found in Watcher.")
        except requests.exceptions.RequestException as e:
            self.error(f"API request error while fetching site ID for domain '{domain}': {str(e)}")
        return None

    def remove_monitor(self, domain, source_ref):
        """Remove a domain from monitoring."""
        site_id = self.get_site_id(domain)
        if not site_id:
            self.error(f"Unable to retrieve site ID for domain '{domain}'.")

        try:
            response = requests.delete(
                f"{self.watcher_url}{site_id}/",
                headers=self.headers,
                verify=False
            )
            response.raise_for_status()

            response_data = response.json() if response.content else {}

            return {
                "Message": f"Domain '{domain}' successfully removed from monitoring.",
                "WatcherResponse": response_data
            }
        except requests.exceptions.RequestException as e:
            self.error(f"Failed to remove domain '{domain}' from monitoring: {str(e)}")

    def run(self):
        Responder.run(self)
        artifact_data = self.get_data()

        is_valid, domain = self.validate_artifact(artifact_data)
        if not is_valid:
            self.error("Invalid observable data type. Only 'domain' is supported.")

        source_ref = self.extract_source_ref(artifact_data)
        if not source_ref:
            self.error(f"Missing {self.the_hive_custom_field} in the provided data.")

        if self.service == "WatcherAddDomain":
            report = self.add_monitor(domain, source_ref)
        elif self.service == "WatcherRemoveDomain":
            report = self.remove_monitor(domain, source_ref)
        else:
            self.error("Invalid service specified.")

        # Send the report
        self.report(report)

if __name__ == "__main__":
    Watcher_MonitorManager().run()
