#!/usr/bin/env python3

# Author: THA-CERT // YNE

import requests
import json
from cortexutils.analyzer import Analyzer


class Watcher_Check(Analyzer):
    def __init__(self):
        super().__init__()

        # Load URL and API key from config
        base_url = self.get_param("config.watcher_url", None, "Watcher URL is missing.")
        self.watcher_url = f"{base_url.rstrip('/')}/api/"
        self.watcher_api_key = self.get_param(
            "config.watcher_api_key", None, "Watcher API key is missing."
        )

        # Set headers
        self.headers = {
            "Authorization": f"Token {self.watcher_api_key}",
            "Content-Type": "application/json",
        }

    def _get_all_paginated_results(self, url, params=None):
        """
        Fetch all results from a paginated API endpoint.
        Returns a list of all items across all pages.
        """
        all_results = []
        current_url = url
        
        try:
            while current_url:
                response = requests.get(
                    current_url,
                    headers=self.headers,
                    params=params if current_url == url else None,
                    verify=False
                )
                response.raise_for_status()
                data = response.json()
                
                if isinstance(data, dict) and 'results' in data:
                    all_results.extend(data['results'])
                    current_url = data.get('next')
                else:
                    all_results.extend(data if isinstance(data, list) else [])
                    break
                    
            return all_results
            
        except requests.exceptions.RequestException as e:
            self.error(f"Failed to fetch paginated results: {str(e)}")
            return []

    # ===== WEBSITE MONITORING OPERATIONS =====

    def get_website_monitoring_domain(self, domain_name):
        """Check if domain exists in Website Monitoring and return details."""
        try:
            sites = self._get_all_paginated_results(
                f"{self.watcher_url}site_monitoring/site/"
            )
            
            for site in sites:
                if site.get("domain_name") == domain_name:
                    # Process MX records
                    mx_list = []
                    mx_raw = site.get("MX_records")
                    
                    if mx_raw:
                        try:
                            entries = (
                                mx_raw
                                if isinstance(mx_raw, list)
                                else mx_raw.strip("[]").split(",")
                            )
                            
                            for entry in entries:
                                if entry and str(entry).strip():
                                    mx_clean = str(entry).split()[-1].strip(" .'\"]")
                                    if mx_clean:
                                        mx_list.append(mx_clean)
                        except Exception:
                            pass

                    return {
                        "found": True,
                        "domain_name": site.get("domain_name"),
                        "Ticket ID": site.get("ticket_id") or "-",
                        "legitimacy": site.get("legitimacy") or "-",
                        "Ip": site.get("ip") or "-",
                        "Ip Second": site.get("ip_second") or "-",
                        "MX Records": mx_list if mx_list else ["-"],
                        "Mail Server": site.get("mail_A_record_ip") or "-",
                        "takedown_request": site.get("takedown_request", False),
                        "legal_team": site.get("legal_team", False),
                        "blocking_request": site.get("blocking_request", False),
                        "created_at": site.get("created_at") or "-",
                        "updated_at": site.get("updated_at") or "-"
                    }
            
            return {"found": False}
            
        except Exception as e:
            self.error(f"Failed to check Website Monitoring: {str(e)}")

    # ===== LEGITIMATE DOMAIN OPERATIONS =====

    def get_legitimate_domain(self, domain_name):
        """Check if domain exists in Legitimate Domain module and return details."""
        try:
            domains = self._get_all_paginated_results(
                f"{self.watcher_url}common/legitimate_domains/",
                params={"search": domain_name}
            )
            
            for domain in domains:
                if domain.get("domain_name") == domain_name:
                    return {
                        "found": True,
                        "domain_name": domain.get("domain_name"),
                        "Ticket ID": domain.get("ticket_id") or "-",
                        "repurchased": domain.get("repurchased", False),
                        "contact": domain.get("contact") or "-",
                        "created_at": domain.get("created_at") or "-",
                        "updated_at": domain.get("updated_at") or "-",
                        "id": domain.get("id")
                    }
            
            return {"found": False}
        except Exception as e:
            self.error(f"Failed to check Legitimate Domain: {str(e)}")

    # ===== SUMMARY =====

    def summary(self, raw):
        """Generate a summary for TheHive taxonomies."""
        taxonomies = []
        namespace = "Watcher"
        predicate = "Check"
        
        status = raw.get("status", "NotFound")
        
        # Determine level based on status
        if status in ["FoundOnLegitDomain", "FoundOnWebsiteMonitoring", "FoundOnBoth"]:
            level = "safe"
        else:
            level = "info"
        
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, status))

        return {"taxonomies": taxonomies}

    def run(self):
        try:
            data = self.get_data()
            if not data:
                self.error("No data received from Cortex. Cannot proceed.")
                return

            # Handle both string and dict formats
            if isinstance(data, str):
                try:
                    if data.strip() and not data.startswith("{"):
                        data = json.loads(f'{{"data": "{data}"}}')
                except json.JSONDecodeError as e:
                    self.error(f"Invalid JSON received: {str(e)}")
                    return

            domain = data.get("data")
            if not domain or not isinstance(domain, str):
                self.error("Invalid input: Domain name is missing or not a string.")
                return
            
            # Check both modules
            legit_result = self.get_legitimate_domain(domain)
            monitoring_result = self.get_website_monitoring_domain(domain)
            
            legit_found = legit_result.get("found", False)
            monitoring_found = monitoring_result.get("found", False)
            
            result = {
                "domain_name": domain,
                "LegitDomain": legit_result if legit_found else None,
                "WebsiteMonitoring": monitoring_result if monitoring_found else None
            }
            
            if legit_found and monitoring_found:
                result["status"] = "FoundOnBoth"
                result["Message"] = f"Domain '{domain}' is found on both Legitimate Domain and Website Monitoring modules."
            elif legit_found:
                result["status"] = "FoundOnLegitDomain"
                result["Message"] = f"Domain '{domain}' is Legitimate Domain."
            elif monitoring_found:
                result["status"] = "FoundOnWebsiteMonitoring"
                result["Message"] = f"Domain '{domain}' is on Monitoring."
            else:
                result["status"] = "NotFound"
                result["Message"] = f"Domain '{domain}' is not found on any Watcher module."
            
            self.report(result)
            
        except Exception as e:
            self.error(f"Unexpected error: {str(e)}")


if __name__ == "__main__":
    Watcher_Check().run()
