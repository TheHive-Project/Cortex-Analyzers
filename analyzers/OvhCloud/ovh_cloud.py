#!/usr/bin/env python3
# Author: THA-CERT

from cortexutils.analyzer import Analyzer
from time import sleep

import ovh
import json
import tldextract


class OvhCloud(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        # Set configuration variables
        self.service = self.get_param("config.service", None, "Service parameter is missing")
        self.autoimport_tags = self.get_param("config.autoimport_tags", True)
        self.endpoint = self.get_param("config.API_endpoint", None, "API endpoint is missing")
        ovh_subsidiary = self.get_param("config.API_ovh_subsidiary", None)

        # Check API endpoint
        if self.endpoint not in ["ovh-eu", "ovh-us", "ovh-ca"]:
            self.error("Invalid API endpoint, should be 'ovh-eu', 'ovh-us' or 'ovh-ca'")

        # Check or set default OVH Subsidiary
        ovh_eu = ["CZ", "DE", "ES", "EU", "FI", "FR", "GB", "IE", "IT", "LT", "MA", "NL", "PL", "PT", "SN", "TN"]
        ovh_us = ["ASIA", "AU", "CA", "CZ", "DE", "ES", "EU", "FI", "FR", "GB", "IE", "IT", "LT", "MA", "NL", "PL", "PT", "QC", "SG", "SN", "TN", "US", "WE", "WS"]
        ovh_ca = ["ASIA", "AU", "CA", "IN", "QC", "SG", "WE", "WS"]
        if ovh_subsidiary is not None: # Check
            if ovh_subsidiary in locals()[self.endpoint.replace('-', '_')]:
                self.ovh_subsidiary = ovh_subsidiary
            else:
                self.error(f"Invalid OVH Subsidiary '{ovh_subsidiary}' for endpoint {self.endpoint}, should be in: {locals()[self.endpoint.replace('-', '_')]}")
        else: # Set default
            self.ovh_subsidiary = self.endpoint.split('-')[1].upper()

        # Vars init
        self.domain = tldextract.TLDExtract(cache_dir=None)(self.get_data()).top_domain_under_public_suffix
        if self.domain == "":
            self.error("Invalid observable (not containing valid Domain Name)")

        # Set API client
        self.client = ovh.Client(
            endpoint=self.endpoint,
            application_key=self.get_param("config.API_ak", None, "API Application key is missing"),
            application_secret=self.get_param("config.API_as", None, "API Application secret is missing"),
            consumer_key=self.get_param("config.API_cs", None, "API Consumer secret is missing")
        )


    def run(self):
        Analyzer.run(self)

        # Init analyzer report
        self.output = {
            "report": {},
            "tags": []
        }
        self.output["report"]["endpoint"] = self.endpoint
        self.output["report"]["subsidiary"] = self.ovh_subsidiary

        # Check if a Domain Name is available for purchase
        if self.service == "OvhDomainCheck":
            # Create a cart
            cart_id = self.create_cart()
            # Request domain information
            domain_info = self.get_domain_info(cart_id)
            self.output["domain_info"] = domain_info
            if domain_info == []:
                domain_info = [{}] # Set empty dict, to proceed next checks without error (Domain Name not available).

            # Get Total price
            price = None
            currency = None
            for p in domain_info[0].get("prices", []):
                if p.get("label", "") == "TOTAL":
                    price = p.get("price", {}).get("value", False)
                    currency = p.get("price", {}).get("currencyCode", False)

            if price:
                self.output["report"]["price"] = "%.2f" % price + " " + str(currency).lower()

            # Get domain offer details ("Pricing Mode")
            self.output["report"]["action"] = domain_info[0].get("action", None)
            self.output["report"]["pricing_mode"] = domain_info[0].get("pricingMode", None)

            # Check if domain is available ('create')
            if self.output["report"]["action"] == "create":
                self.output["report"]["status"] = "available"
                self.output["report"]["message"] = f"{self.domain} is {self.output["report"]["status"]} for {self.output["report"]["price"]}."
                self.output["tags"].append("available")
                self.output["tags"].append(f"price:{self.output["report"]["price"]}")
            else:
                # Check if domain is for sale ('transfer-aftermarketX')
                if str(self.output["report"]["pricing_mode"]).startswith("transfer-aftermarket"):
                    self.output["report"]["status"] = "for sale"
                    self.output["report"]["message"] = f"{self.domain} is {self.output["report"]["status"]} on an aftermarket platform ({self.output["report"]["action"]}) for {self.output["report"]["price"]}."
                    self.output["tags"].append("for_sale")
                    self.output["tags"].append(f"price:{self.output["report"]["price"]}")
                # Domain is not available
                else:
                    self.output["tags"].append("not_available")
                    self.output["report"]["status"] = "not available"
                    self.output["report"]["message"] = f"{self.domain} is {self.output["report"]["status"]}."

        self.report(self.output)


    def summary(self, raw):
        # Default short template
        taxonomies = []
        level = "info"
        namespace = "OVH"
        predicate = "Check"

        status = raw.get("report", {}).get("status", None)
        if status == "available": # Green: available
            level = "safe"
        elif status is None: # Orange: error while getting status
            level = "warning"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, str(status)))
        return {"taxonomies": taxonomies}


    def operations(self, raw):
        operations = []

        for tag in raw.get("tags", []):
            if self.autoimport_tags and tag not in self.get_param("tags", []):
                operations.append(self.build_operation("AddTagToArtifact", tag=f"ovh:{str(tag)}"))

        return operations


    # Functions for API calls, matching OVH Cloud API documentation (Eg: https://eu.api.ovh.com/console/?branch=v1)
    def create_cart(self, retry=3, interval=2):
        error = ""
        while retry > 0:
            try:
                r = self.client.post(
                    "/order/cart",
                    description="Check domain availability: " + self.domain,
                    ovhSubsidiary=self.ovh_subsidiary,
                )
                return r.get("cartId", None)

            except Exception as e:
                sleep(interval)
                retry -= 1
                error = e

        self.error(f"Error while creating cart: {error}")


    def get_domain_info(self, cart_id, retry=3, interval=2):
        error = ""
        while retry > 0:
            try:
                r = self.client.get(f"/order/cart/{cart_id}/domain", domain=self.domain)
                return r

            except Exception as e:
                sleep(interval)
                retry -= 1
                error = e

        if str(error).startswith("Some parameters are invalid in the request: Check failed."): # Seen when TLD is not managed by OVH endpoint / subsidiary.
            self.output["report"]["details"] = f"TLD possibly not managed by OVH endpoint / subsidiary. Error message: {error}."
            self.output["tags"].append("unmanaged_TLD")
            return []
        else:
            self.error(f"Error while getting available offers: {error}")


if __name__ == "__main__":
    OvhCloud().run()
