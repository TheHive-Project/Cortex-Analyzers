#!/usr/bin/env python3
# Author: THA-CERT // YNE

import requests
from cortexutils.responder import Responder


class Watcher_MonitorManager(Responder):
    def __init__(self):
        super().__init__()

        # Load URL and API key from config
        base_url = self.get_param("config.watcher_url", None, "Watcher URL is missing.")
        self.watcher_url = f"{base_url.rstrip('/')}/api/"
        self.watcher_api_key = self.get_param(
            "config.watcher_api_key", None, "Watcher API key is missing."
        )
        self.the_hive_custom_field = self.get_param(
            "config.the_hive_custom_field", "watcher-id", "Custom Field is missing."
        )
        self.service = self.get_param(
            "config.service", None, "Service parameter is missing."
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
                
                # Handle paginated response
                if isinstance(data, dict) and 'results' in data:
                    all_results.extend(data['results'])
                    current_url = data.get('next')
                # Handle list response
                elif isinstance(data, list):
                    all_results.extend(data)
                    break
                # Handle single object response
                else:
                    all_results.append(data)
                    break
                    
            return all_results
            
        except requests.exceptions.RequestException as e:
            self.error(f"Failed to fetch paginated results: {str(e)}")
            return []

    def validate_artifact(self, data):
        """Validate if the artifact type is supported (only 'domain' is accepted)."""
        domain = data.get("data", None)
        artifact_type = data.get("dataType", None)

        if artifact_type != "domain":
            self.error("Invalid artifact type. Only 'domain' artifacts are supported.")

        return domain

    def extract_source_ref(self, data):
        """Extract sourceRef (watcher-id) from the provided data, if available."""
        container = data.get("alert") or data.get("case", {})
        custom_fields = container.get("customFieldValues", {})

        # Get the custom field value
        field_value = custom_fields.get(self.the_hive_custom_field, None)

        if isinstance(field_value, list):
            return field_value[0] if field_value else None

        return field_value

    def extract_tags(self, data):
        """Extract watcher:* tags from TheHive observable tags."""
        tags = data.get("tags", [])
        watcher_tags = {}

        for tag in tags:
            if tag.startswith("watcher:"):
                # Remove 'watcher:' prefix
                key_value = tag.replace("watcher:", "")

                # Remove escaped quotes (from taxonomy tags)
                key_value = key_value.replace("\\", "")
                key_value = key_value.replace('"', "")

                if "=" in key_value:
                    key, value = key_value.split("=", 1)
                    watcher_tags[key.strip()] = value.strip()

        return watcher_tags

    def validate_module_tag(self, watcher_tags):
        """Validate the watcher:module tag."""
        module = watcher_tags.get("module")

        if not module:
            self.error(
                "Tag watcher:module is required (LegitDomain or WebsiteMonitoring)."
            )

        # Convert to proper case for validation
        module_normalized = module.strip()

        valid_modules = {
            "legitdomain": "LegitDomain",
            "websitemonitoring": "WebsiteMonitoring",
        }

        module_lower = module_normalized.lower()

        if module_lower not in valid_modules:
            self.error(
                "Tag watcher:module must be 'LegitDomain' or 'WebsiteMonitoring' (case-insensitive)."
            )

        return valid_modules[module_lower]

    # ===== LEGITIMATE DOMAIN OPERATIONS =====

    def get_legitimate_domain(self, domain_name):
        """Get legitimate domain details from Watcher API."""
        try:
            domains = self._get_all_paginated_results(
                f"{self.watcher_url}common/legitimate_domains/",
                params={"search": domain_name}
            )

            for domain in domains:
                if domain.get("domain_name") == domain_name:
                    return domain

            return None

        except requests.exceptions.RequestException as e:
            self.error(f"API error checking legitimate domains: {str(e)}")
            return None

    def add_legit_domain(self, domain, source_ref, watcher_tags):
        """Add domain to legitimate domains list."""
        # Check if domain already exists
        existing = self.get_legitimate_domain(domain)

        if existing:
            self.error(f"Domain '{domain}' already exists in Legitimate Domain module.")

        # Validate repurchased tag
        if "repurchased" not in watcher_tags:
            self.error("Tag watcher:repurchased is required (Yes or No).")

        if watcher_tags["repurchased"] not in ["Yes", "No"]:
            self.error("Tag watcher:repurchased must be 'Yes' or 'No'.")

        # Create new legitimate domain
        payload = {
            "domain_name": domain,
            "ticket_id": source_ref,
            "repurchased": watcher_tags["repurchased"] == "Yes",
        }

        if "contact" in watcher_tags:
            payload["contact"] = watcher_tags["contact"]

        try:
            response = requests.post(
                f"{self.watcher_url}common/legitimate_domains/",
                headers=self.headers,
                json=payload,
                verify=False,
            )
            response.raise_for_status()

            return {
                "success": True,
                "message": f"Domain '{domain}' successfully added to Legitimate Domain module.",
                "full": response.json() if response.content else {}
            }
        except requests.exceptions.RequestException as e:
            self.error(f"Failed to add legitimate domain '{domain}': {str(e)}")

    def update_legit_domain(self, domain, source_ref, watcher_tags):
        """Update domain information in legitimate domains list."""
        # Check if domain exists
        existing = self.get_legitimate_domain(domain)

        if not existing:
            self.error(f"Domain '{domain}' not found in Legitimate Domain module.")

        # Build update payload
        payload = {}
        updated_fields = []

        # Always update ticket_id if different
        if existing.get("ticket_id") != source_ref:
            payload["ticket_id"] = source_ref
            updated_fields.append(f"ticket_id: '{existing.get('ticket_id')}' → '{source_ref}'")

        # Update repurchased status if tag is present
        if "repurchased" in watcher_tags:
            if watcher_tags["repurchased"] not in ["Yes", "No"]:
                self.error("Tag watcher:repurchased must be 'Yes' or 'No'.")

            new_repurchased = watcher_tags["repurchased"] == "Yes"
            if existing.get("repurchased") != new_repurchased:
                payload["repurchased"] = new_repurchased
                updated_fields.append(f"repurchased: {existing.get('repurchased')} → {new_repurchased}")

        # Update contact if tag is present
        if "contact" in watcher_tags:
            new_contact = watcher_tags["contact"]
            if existing.get("contact") != new_contact:
                payload["contact"] = new_contact
                updated_fields.append(f"contact: '{existing.get('contact')}' → '{new_contact}'")

        # If no fields changed, return error
        if not payload:
            self.error("No updates detected. All fields are already up-to-date.")

        try:
            response = requests.patch(
                f"{self.watcher_url}common/legitimate_domains/{existing['id']}/",
                headers=self.headers,
                json=payload,
                verify=False,
            )
            response.raise_for_status()

            return {
                "success": True,
                "message": f"Domain '{domain}' successfully updated in Legitimate Domain module. Updated: {', '.join(updated_fields)}",
                "full": response.json() if response.content else {}
            }
        except requests.exceptions.RequestException as e:
            self.error(f"Failed to update legitimate domain '{domain}': {str(e)}")

    def remove_legit_domain(self, domain, source_ref):
        """Remove domain from legitimate domains list."""
        existing = self.get_legitimate_domain(domain)

        if not existing:
            self.error(f"Domain '{domain}' not found in Legitimate Domain module.")

        try:
            response = requests.delete(
                f"{self.watcher_url}common/legitimate_domains/{existing['id']}/",
                headers=self.headers,
                verify=False,
            )
            response.raise_for_status()

            return {
                "success": True,
                "message": f"Domain '{domain}' successfully removed from Legitimate Domain module.",
                "full": response.json() if response.content else {}
            }
        except requests.exceptions.RequestException as e:
            self.error(f"Failed to remove legitimate domain '{domain}': {str(e)}")

    # ===== WEBSITE MONITORING OPERATIONS =====

    def is_domain_already_monitored(self, domain):
        """Check if the domain is already being monitored."""
        try:
            sites = self._get_all_paginated_results(
                f"{self.watcher_url}site_monitoring/site/"
            )

            for site in sites:
                if site.get("domain_name") == domain:
                    return True
            return False
        except requests.exceptions.RequestException as e:
            self.error(f"API error checking monitored domains: {str(e)}")
            return False

    def get_website_monitoring_domain(self, domain_name):
        """Get website monitoring domain details."""
        try:
            sites = self._get_all_paginated_results(
                f"{self.watcher_url}site_monitoring/site/"
            )

            for site in sites:
                if site.get("domain_name") == domain_name:
                    return site

            return None

        except requests.exceptions.RequestException as e:
            self.error(f"API error checking website monitoring: {str(e)}")
            return None

    def add_website_monitoring_domain(self, domain, source_ref, watcher_tags):
        """Add domain to Website Monitoring."""
        # Validate legitimacy value
        legitimacy = watcher_tags.get("legitimacy")
        if not legitimacy:
            self.error("Tag watcher:legitimacy is required (2-6).")

        try:
            legitimacy_value = int(legitimacy)
            if not (2 <= legitimacy_value <= 6):
                self.error("Tag watcher:legitimacy must be between 2 and 6.")
        except ValueError:
            self.error("Tag watcher:legitimacy must be a valid integer.")

        # Check if domain already exists
        if self.is_domain_already_monitored(domain):
            self.error(f"Domain '{domain}' already in Website Monitoring module.")

        # Add new monitoring
        payload = {
            "action": "add",
            "domain_name": domain,
            "ticket_id": source_ref,
            "legitimacy": legitimacy_value,
            "takedown_request": watcher_tags.get("takedown_request", "No") == "Yes",
            "legal_team": watcher_tags.get("legal_team", "No") == "Yes",
            "blocking_request": watcher_tags.get("blocking_request", "No") == "Yes",
        }

        try:
            response = requests.post(
                f"{self.watcher_url}site_monitoring/site/",
                headers=self.headers,
                json=payload,
                verify=False,
            )
            response.raise_for_status()

            return {
                "success": True,
                "message": f"Domain '{domain}' successfully added to Website Monitoring module.",
                "full": response.json() if response.content else {}
            }
        except requests.exceptions.RequestException as e:
            self.error(f"Failed to add domain '{domain}': {str(e)}")

    def update_website_monitoring_domain(self, domain, source_ref, watcher_tags):
        """Update domain information in Website Monitoring."""
        # Check if domain exists
        existing = self.get_website_monitoring_domain(domain)

        if not existing:
            self.error(f"Domain '{domain}' not found in Website Monitoring module.")

        # Build update payload
        payload = {}
        updated_fields = []

        # Always update ticket_id if different
        if existing.get("ticket_id") != source_ref:
            payload["ticket_id"] = source_ref
            updated_fields.append(f"ticket_id: '{existing.get('ticket_id')}' → '{source_ref}'")

        # Update legitimacy if tag is present
        if "legitimacy" in watcher_tags:
            try:
                legitimacy_value = int(watcher_tags["legitimacy"])
                if not (2 <= legitimacy_value <= 6):
                    self.error("Tag watcher:legitimacy must be between 2 and 6.")

                if existing.get("legitimacy") != legitimacy_value:
                    payload["legitimacy"] = legitimacy_value
                    updated_fields.append(f"legitimacy: {existing.get('legitimacy')} → {legitimacy_value}")
            except ValueError:
                self.error("Tag watcher:legitimacy must be a valid integer.")

        # Update boolean flags if tags are present
        bool_flags = [
            ("takedown_request", "watcher:takedown_request"),
            ("legal_team", "watcher:legal_team"),
            ("blocking_request", "watcher:blocking_request"),
        ]

        for field_name, tag_name_full in bool_flags:
            tag_key = tag_name_full.replace("watcher:", "")
            if tag_key in watcher_tags:
                new_value = watcher_tags[tag_key] == "Yes"
                if existing.get(field_name) != new_value:
                    payload[field_name] = new_value
                    updated_fields.append(f"{field_name}: {existing.get(field_name)} → {new_value}")

        # If no fields changed, return error
        if not payload:
            self.error("No updates detected. All fields are already up-to-date.")

        try:
            site_id = existing.get("id")
            response = requests.patch(
                f"{self.watcher_url}site_monitoring/site/{site_id}/",
                headers=self.headers,
                json=payload,
                verify=False,
            )
            response.raise_for_status()

            return {
                "success": True,
                "message": f"Domain '{domain}' successfully updated in Website Monitoring. Updated: {', '.join(updated_fields)}",
                "full": response.json() if response.content else {}
            }
        except requests.exceptions.RequestException as e:
            self.error(f"Failed to update domain '{domain}': {str(e)}")

    def get_site_id(self, domain):
        """Get the site ID for a domain."""
        try:
            sites = self._get_all_paginated_results(
                f"{self.watcher_url}site_monitoring/site/"
            )

            for site in sites:
                if site.get("domain_name") == domain:
                    return site.get("id")

            return None
        except requests.exceptions.RequestException as e:
            self.error(f"API error fetching site ID for '{domain}': {str(e)}")
            return None

    def remove_website_monitoring_domain(self, domain, source_ref):
        """Remove domain from Website Monitoring."""
        site_id = self.get_site_id(domain)
        if not site_id:
            self.error(f"Domain '{domain}' not found in Website Monitoring module.")

        try:
            response = requests.delete(
                f"{self.watcher_url}site_monitoring/site/{site_id}/",
                headers=self.headers,
                verify=False,
            )
            response.raise_for_status()

            return {
                "success": True,
                "message": f"Domain '{domain}' successfully removed from Website Monitoring module.",
                "full": response.json() if response.content else {}
            }
        except requests.exceptions.RequestException as e:
            self.error(f"Failed to remove domain '{domain}': {str(e)}")

    # ===== TRANSFER OPERATIONS =====

    def transfer_to_legit_domain(self, domain, source_ref, watcher_tags):
        """Transfer domain FROM Website Monitoring TO Legitimate Domain."""
        # Validate repurchased tag (MANDATORY for destination)
        if "repurchased" not in watcher_tags:
            self.error(
                "Tag watcher:repurchased is required for transfer to Legitimate Domain (Yes or No)."
            )

        if watcher_tags["repurchased"] not in ["Yes", "No"]:
            self.error("Tag watcher:repurchased must be 'Yes' or 'No'.")

        # Verify domain exists in Website Monitoring (source)
        site_id = self.get_site_id(domain)
        if not site_id:
            self.error(f"Domain '{domain}' not found in Website Monitoring module.")

        # Check if already in Legitimate Domain (destination)
        existing = self.get_legitimate_domain(domain)
        if existing:
            self.error(f"Domain '{domain}' already exists in Legitimate Domain module.")

        # Remove from Website Monitoring
        try:
            requests.delete(
                f"{self.watcher_url}site_monitoring/site/{site_id}/",
                headers=self.headers,
                verify=False,
            )
        except Exception as e:
            self.error(f"Failed to remove from Website Monitoring: {str(e)}")

        # Add to Legitimate Domain
        payload = {
            "domain_name": domain,
            "ticket_id": source_ref,
            "repurchased": watcher_tags["repurchased"] == "Yes",
        }

        if "contact" in watcher_tags:
            payload["contact"] = watcher_tags["contact"]

        try:
            response = requests.post(
                f"{self.watcher_url}common/legitimate_domains/",
                headers=self.headers,
                json=payload,
                verify=False,
            )
            response.raise_for_status()

            return {
                "success": True,
                "message": f"Domain '{domain}' transferred: Website Monitoring → Legitimate Domain (repurchased={watcher_tags['repurchased']}).",
                "full": response.json() if response.content else {}
            }
        except requests.exceptions.RequestException as e:
            self.error(f"Failed to transfer domain: {str(e)}")

    def transfer_to_website_monitoring(self, domain, source_ref, watcher_tags):
        """Transfer domain FROM Legitimate Domain TO Website Monitoring."""
        # Validate legitimacy (MANDATORY for destination)
        legitimacy = watcher_tags.get("legitimacy")
        if not legitimacy:
            self.error(
                "Tag watcher:legitimacy is required for transfer to WebsiteMonitoring (2-6)."
            )

        try:
            legitimacy_value = int(legitimacy)
            if not (2 <= legitimacy_value <= 6):
                self.error("Tag watcher:legitimacy must be between 2 and 6.")
        except ValueError:
            self.error("Tag watcher:legitimacy must be a valid integer.")

        # Verify domain exists in Legitimate Domain (source)
        existing = self.get_legitimate_domain(domain)
        if not existing:
            self.error(f"Domain '{domain}' not found in Legitimate Domain module.")

        # Check if already in Website Monitoring (destination)
        if self.is_domain_already_monitored(domain):
            self.error(f"Domain '{domain}' already in Website Monitoring module.")

        # Remove from Legitimate Domain
        try:
            requests.delete(
                f"{self.watcher_url}common/legitimate_domains/{existing['id']}/",
                headers=self.headers,
                verify=False,
            )
        except Exception as e:
            self.error(f"Failed to remove from Legitimate Domain: {str(e)}")

        # Add to Website Monitoring
        payload = {
            "action": "add",
            "domain_name": domain,
            "ticket_id": source_ref,
            "legitimacy": legitimacy_value,
            "takedown_request": watcher_tags.get("takedown_request", "No") == "Yes",
            "legal_team": watcher_tags.get("legal_team", "No") == "Yes",
            "blocking_request": watcher_tags.get("blocking_request", "No") == "Yes",
        }

        try:
            response = requests.post(
                f"{self.watcher_url}site_monitoring/site/",
                headers=self.headers,
                json=payload,
                verify=False,
            )
            response.raise_for_status()

            return {
                "success": True,
                "message": f"Domain '{domain}' transferred: Legitimate Domain → Website Monitoring (legitimacy={legitimacy_value}).",
                "full": response.json() if response.content else {}
            }
        except requests.exceptions.RequestException as e:
            self.error(f"Failed to transfer domain: {str(e)}")

    # ===== INTELLIGENT ROUTING =====

    def run(self):
        try:
            data = self.get_data()

            # Validate artifact and get domain
            domain = self.validate_artifact(data)

            # Extract tags
            watcher_tags = self.extract_tags(data)

            # Extract source reference (watcher-id)
            source_ref = self.extract_source_ref(data)

            # Route based on service
            if self.service == "WatcherAdd":
                module = self.validate_module_tag(watcher_tags)

                if module == "LegitDomain":
                    report = self.add_legit_domain(domain, source_ref, watcher_tags)
                else:  # WebsiteMonitoring
                    report = self.add_website_monitoring_domain(domain, source_ref, watcher_tags)

            elif self.service == "WatcherRemove":
                module = self.validate_module_tag(watcher_tags)

                if module == "LegitDomain":
                    report = self.remove_legit_domain(domain, source_ref)
                else:  # WebsiteMonitoring
                    report = self.remove_website_monitoring_domain(domain, source_ref)

            elif self.service == "WatcherUpdate":
                module = self.validate_module_tag(watcher_tags)

                if module == "LegitDomain":
                    report = self.update_legit_domain(domain, source_ref, watcher_tags)
                else:  # WebsiteMonitoring
                    report = self.update_website_monitoring_domain(domain, source_ref, watcher_tags)

            elif self.service == "WatcherTransfer":
                destination_module = self.validate_module_tag(watcher_tags)

                if destination_module == "LegitDomain":
                    report = self.transfer_to_legit_domain(domain, source_ref, watcher_tags)
                else:  # WebsiteMonitoring
                    report = self.transfer_to_website_monitoring(domain, source_ref, watcher_tags)

            else:
                self.error(f"Unknown service '{self.service}'.")

            self.report(report)

        except Exception as e:
            self.error(f"Unexpected error: {str(e)}")


if __name__ == "__main__":
    Watcher_MonitorManager().run()
