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
        """Check if the domain is already being monitored in Watcher and return all relevant info."""
        try:
            response = requests.get(
                self.watcher_url,
                headers=self.headers,
                verify=False
            )
            response.raise_for_status()
            sites = response.json()

            # Domain found
            for site in sites:
                site_domain = str(site.get("domain_name", "")).lower().lstrip("www.")
                input_domain = domain.lower().lstrip("www.")

                if site_domain == input_domain:
                    mx_list = []
                    mx_raw = site.get("MX_records")

                    # Process MX records if present
                    if mx_raw:
                        try:
                            entries = mx_raw if isinstance(mx_raw, list) else mx_raw.strip("[]").split(",")
                            
                            for entry in entries:
                                if entry and str(entry).strip():
                                    mx_clean = str(entry).split()[-1].strip(" .'\"]")
                                    if mx_clean:
                                        mx_list.append(mx_clean)
                        except Exception as e:
                            self.error(f"Failed to parse MX_records: {str(e)}")

                    
                    return {
                        "status": "Monitored",
                        "Message": f"Domain '{domain}' is already monitored by Watcher.",
                        "Ticket ID": site.get("ticket_id") or "-",
                        "Ip": site.get("ip") or "-",
                        "Ip Second": site.get("ip_second") or "-",
                        "MX Records": mx_list or "-",
                        "Mail Server": site.get("mail_A_record_ip") or "-"
                    }

            # Domain not found
            return {
                "status": "Not Monitored",
                "Message": f"Domain '{domain}' is not monitored by Watcher."
            }

        except requests.exceptions.RequestException as e:
            self.error(f"API request error while checking monitored domains: {str(e)}")
            return {
                "status": "Error",
                "Message": f"Failed to query Watcher: {str(e)}"
            }

    def summary(self, raw):
        """Generate a summary for TheHive taxonomies."""
        taxonomies = []
        namespace = "Watcher"
        predicate = "Check"
        status = raw.get("status", "Not Monitored")

        level = "safe" if status == "Monitored" else "info"
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, status))

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        """Generate artifacts for TheHive."""
        artifacts = []
        
        if raw.get("status") != "Monitored":
            return artifacts
        
        # Add IPs
        for field in ["Ip", "Ip Second", "Mail Server"]:
            ip = raw.get(field)
            if ip and ip != "-":
                artifacts.append(self.build_artifact("ip", ip))
        
        # Add MX Records
        for mx in raw.get("MX Records", []):
            if mx and mx != "-":
                if "." in mx:
                    parts = mx.split('.')
                    if len(parts) > 2:
                        artifacts.append(self.build_artifact("fqdn", mx))
                    else:
                        artifacts.append(self.build_artifact("domain", mx))
                else:
                    artifacts.append(self.build_artifact("other", mx))
        
        return artifacts

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

            result = self.check_domain_status(domain)
            self.report(result)

        except Exception as e:
            self.error(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    Watcher_CheckDomain().run()