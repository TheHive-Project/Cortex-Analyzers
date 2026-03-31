#!/usr/bin/env python3
# Author: THA-CERT

from cortexutils.responder import Responder
from thehive4py import TheHiveApi
from time import sleep

import ovh
import json
import tldextract


class OvhCloud(Responder):
    def __init__(self):
        Responder.__init__(self)

        # Set configuration variables
        self.service = self.get_param("config.service", None, "Service parameter is missing")
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
        self.domain = tldextract.TLDExtract(cache_dir=None)(self.get_data().get("data", "")).top_domain_under_public_suffix
        if self.domain == "":
            self.error("Invalid observable (not containing valid Domain Name)")

        # Set API client
        self.client = ovh.Client(
            endpoint=self.endpoint,
            application_key=self.get_param("config.API_ak", None, "API Application key is missing"),
            application_secret=self.get_param("config.API_as", None, "API Application secret is missing"),
            consumer_key=self.get_param("config.API_cs", None, "API Consumer secret is missing")
        )
        
        # Set TheHive API, if configuration is provided
        self.thehive_url = self.get_param("config.thehive_url", None)
        self.thehive_token = self.get_param("config.thehive_token", None)
        self.organisation = self.get_param("parameters.organisation", None)
        if self.thehive_url is not None and self.thehive_token is not None:
            self.API = TheHiveApi(
                url=self.thehive_url,
                apikey=self.thehive_token,
                organisation=self.organisation
            )
        else:
            self.API = False


    def run(self):
        Responder.run(self)

        # Init responder report
        self.output = {}
        self.output["endpoint"] = self.endpoint
        self.output["subsidiary"] = self.ovh_subsidiary

        # Action to check or purchase domain name
        if self.service == "OvhDomainOrder":
            # Set service configuration variable
            self.price_limit = self.get_param("config.price_limit", None, "Price limit parameter is missing")
            self.required_configuration = dict()
            for conf in self.get_param("config.required_configuration", [None]):
                if conf is None or ':' not in conf: # Ignore bad parameter(s)
                    continue
                s_conf = conf.split(":")
                # Convert boolean value(s) from str to bool
                if s_conf[-1].lower() == "true":
                    s_conf[-1] = True
                elif s_conf[-1].lower() == "false":
                    s_conf[-1] = False
                # Set value(s)
                self.required_configuration[s_conf[0]] = s_conf[-1]

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
                self.output["price"] = "%.2f" % price + " " + str(currency).lower()

            # Get domain offer details ("Pricing Mode")
            self.output["action"] = domain_info[0].get("action", None)
            self.output["pricing_mode"] = domain_info[0].get("pricingMode", None)

            # Check if domain is available ('create')
            if self.output["action"] == "create":
                self.output["status"] = "available"
                self.output["message"] = f"{self.domain} is {self.output["status"]} for {self.output["price"]}."
            else:
                # Check if domain is for sale ('transfer-aftermarketX')
                if str(self.output["pricing_mode"]).startswith("transfer-aftermarket"):
                    self.output["status"] = "for_sale"
                    self.output["message"] = f"{self.domain} is {self.output["status"]} on an aftermarket platform ({self.output["action"]}) for {self.output["price"]}.".replace('_', ' ')
                # Domain is not available
                else:
                    self.output["status"] = "not_available"
                    self.output["message"] = f"{self.domain} is {self.output["status"]}.".replace('_', ' ')

                self.add_tag_to_thehive(self.output["status"])
                self.error(json.dumps(self.output))
                return
                
            # Check if domain type is 'standard' (not 'premium')
            if self.output["pricing_mode"] not in ["default", "create-default"]:
                self.output["status"] = "not_standard_princing"
                self.output["message"] = f"Domain '{self.domain}' is available, but not with standard pricing ({self.output["status"]}). Not managed by current Responder.".replace('_', ' ')

                self.add_tag_to_thehive(self.output["status"])
                self.error(json.dumps(self.output))
                return

            # Add domain in cart
            item_id = self.add_item_in_chart(cart_id).get("itemId", None)

            # Assign cart
            try:
                self.assign_cart(cart_id)
            except Exception as e:
                # Return error if already assigned. As it's assigned, can continue.
                pass

            # Check if required configuration is needed (Ref.: https://help.ovhcloud.com/csm/en-domain-names-api-order?id=kb_article_view&sysparm_article=KB0051563#fetch-required-configurations)
            self.output["required_conf"] = self.get_item_required_conf(cart_id, item_id)
            for conf in self.output["required_conf"]:
                if conf.get("label", "NO_LABEL") in self.required_configuration.keys():
                    # Add required confirguration
                    self.add_item_required_conf(
                        cart_id,
                        item_id,
                        conf.get("label"),
                        self.required_configuration[conf.get("label")],
                    )
                # Check if required configuration is missing in parameters.
                elif conf.get("required", True):
                    self.output["status"] = "missing_configuration"
                    self.output["message"] = f"Required configuration is missing: {conf.get("label", "UNKNOWN ERROR")}."
                    self.add_tag_to_thehive(self.output["status"])
                    self.error(json.dumps(self.output))
                    return

            # Cart checking, before final validation
            self.output["bill_check"] = self.cart_validation_check(cart_id)

            # Get final price (WITHOUT TAXES)
            price_without_tax = (self.output["bill_check"].get("prices", {}).get("withoutTax", {}).get("value", None))
            if price_without_tax is None:  # Exit in case of error
                self.output["status"] = "price_error"
                self.output["message"] = "Error while checking final cart price list. Not value found for 'withoutTax'."
                self.add_tag_to_thehive(self.output["status"])
                self.error(json.dumps(self.output))
                return
            
            # Check price limit (WITHOUT TAXES)
            if price_without_tax > self.price_limit:
                self.output["status"] = "price:too_expensive"
                self.output["message"] = f"{self.domain} too expensive, limit set at {self.price_limit}, but current price is {self.output["price"]}."
                self.add_tag_to_thehive(self.output["status"])
                self.error(json.dumps(self.output))
                return

            # Validate cart (payment)
            self.output["bill"] = self.cart_validation(cart_id)
            # Get bill information
            self.output["order_number"] = self.output["bill"].get("orderId", None)
            if self.output["order_number"] is None:
                self.output["status"] = "no_order_number"
                self.output["message"] = f"{self.domain} order has been requested, but NO order number was returned. Please, check order status on your OVH Cloud account."
                self.add_tag_to_thehive(self.output["status"])
            else:
                self.output["status"] = "ordered"
                self.output["message"] = f"{self.domain} has been ordered under number '{self.output["order_number"]}'. OVH confirmation should be sent by email."
                self.add_tag_to_thehive(f"order:{self.output["order_number"]}")
                self.report(self.output)
                return

            self.error(json.dumps(self.output))
            return

        # Action to set or update domain redirection
        if self.service == "OvhDomainRedirection":
            # Set service configuration variable
            self.domain_redirection = self.get_param("config.domain_redirection", None, "Domain redirection parameter is missing")

            # Set redirection on parent Domain Name and "www" sub-domain
            self.update_or_set_domain_redirection()
            self.update_or_set_domain_redirection("www")
            # Refresh DNS zone to apply changes
            self.apply_domain_redirection()

            self.output["status"] = "redirected"
            self.output["message"] = f"{self.domain} parent domain and 'www' subdomain, have been redirected to '{self.domain_redirection}'."
            self.add_tag_to_thehive(self.output["status"])

            self.report(self.output)
            return

        self.report(self.output)


    def add_tag_to_thehive(self, tag):
        if self.API: # If TheHive API is set, add tag to observable
            current_tags = self.get_data().get("tags", [])
            if f"ovh:{tag}" not in self.get_data().get("tags", []):
                current_tags.append(f"ovh:{tag}")
            r = self.API.observable.update(self.get_data().get("_id", None), {"tags": current_tags})
        
        return r


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
            self.output["details"] = f"TLD possibly not managed by OVH endpoint / subsidiary. Error message: {error}."
            return []
        else:
            self.error(f"Error while getting available offers: {error}")


    def add_item_in_chart(self, cart_id, retry=3, interval=2):
        error = ""
        while retry > 0:
            try:
                r = self.client.post(
                    f"/order/cart/{cart_id}/domain",
                    domain=self.domain,
                    duration="P1Y"
                )
                return r
            except Exception as e:
                sleep(interval)
                retry -= 1
                error = e

        self.error(f"Error while adding item to cart: {error}")


    def assign_cart(self, cart_id):
        r = self.client.post(f"/order/cart/{cart_id}/assign")
        return r


    def get_item_required_conf(self, cart_id, item_id, retry=3, interval=2):
        error = ""
        while retry > 0:
            try:
                r = self.client.get(
                    f"/order/cart/{cart_id}/item/{item_id}/requiredConfiguration"
                )
                return r
            except Exception as e:
                sleep(interval)
                retry -= 1
                error = e

        self.error(f"Error while requesting required conf: {error}")


    def add_item_required_conf(self, cart_id, item_id, label, value, retry=3, interval=2):
        error = ""
        while retry > 0:
            try:
                r = self.client.post(
                    f"/order/cart/{cart_id}/item/{item_id}/configuration",
                    label=label,
                    value=value,
                )
                return r
            except Exception as e:
                sleep(interval)
                retry -= 1
                error = e

        self.error(f"Error while adding item conf: {error}")


    def cart_validation_check(self, cart_id, retry=3, interval=2):
        error = ""
        while retry > 0:
            try:
                r = self.client.get(f"/order/cart/{cart_id}/checkout")
                return r
            except Exception as e:
                sleep(interval)
                retry -= 1
                error = e

        self.error(f"Error while checking cart. Error message: {error}")


    def cart_validation(self, cart_id, retry=3, interval=2):
        error = ""
        while retry > 0:
            try:
                r = self.client.post(
                    f"/order/cart/{cart_id}/checkout",
                    autoPayWithPreferredPaymentMethod=True,
                    waiveRetractationPeriod=True,
                )
                return r
            except Exception as e:
                sleep(interval)
                retry -= 1
                error = e

        self.error(f"Error while validating cart: {error}")


    def get_domain_redirection(self, sub_domain="", retry=3, interval=2):
        error = ""
        while retry > 0:
            try:
                r = self.client.get(
                    f"/domain/zone/{self.domain}/redirection",
                    subDomain=sub_domain,
                )
                return r
            except Exception as e:
                sleep(interval)
                retry -= 1
                error = e
        
        if str(error).startswith("This service does not exist \nOVH-Query-ID:"): # Seen when Domain Name is not owned by OVH Cloud account.
            self.add_tag_to_thehive("DN_not_owned")
            self.error(f"Domain Name possibly not owned by OVH Cloud account. Error message: {error}.")

        self.error(f"Error while getting actual redirection for DN {self.domain}: {error}")


    def set_domain_redirection(self, sub_domain="", retry=3, interval=2):
        error = ""
        while retry > 0:
            try:
                r = self.client.post(
                    f"/domain/zone/{self.domain}/redirection",
                    subDomain=sub_domain,
                    target=self.domain_redirection,
                    type="visiblePermanent",
                )
                return r
            except Exception as e:
                sleep(interval)
                retry -= 1
                error = e

        self.error(f"Error while setting new redirection for DN {self.domain}: {error}")


    def update_domain_redirection(self, redirection_id, sub_domain="", retry=3, interval=2):
        error = ""
        while retry > 0:
            try:
                r = self.client.put(
                    f"/domain/zone/{self.domain}/redirection/{redirection_id}",
                    subDomain=sub_domain,
                    target=self.domain_redirection,
                    type="visiblePermanent",
                )
                return r
            except Exception as e:
                sleep(1)
                retry -= 1
                error = e

        self.error(f"Error while updating new redirection for DN {self.domain}: {error}")


    def update_or_set_domain_redirection(self, sub_domain=""):
        r_get = self.get_domain_redirection(sub_domain)
        # Check if a list (of ids) is returned
        if not isinstance(r_get, list):
            self.error(f"Error while getting redirection id for DN {self.domain} and sub-domain '{sub_domain}'")
        # Check if an id exists
        if len(r_get) == 0:
            self.set_domain_redirection(sub_domain)
        elif len(r_get) == 1:
            self.update_domain_redirection(r_get[0], sub_domain)
        else:
            self.error(f"Error while getting redirection id for DN {self.domain} and sub-domain '{sub_domain}' (multiple ids).")


    def apply_domain_redirection(self, retry=3, interval=2):
        error = ""
        while retry > 0:
            try:
                r = self.client.post(f"/domain/zone/{self.domain}/refresh")
                return r
            except Exception as e:
                sleep(interval)
                retry -= 1
                error = e

        self.error(f"Error while refreshing {self.domain} DNS zone: {error}")


if __name__ == "__main__":
    OvhCloud().run()
