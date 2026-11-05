#!/usr/bin/env python3
# encoding: utf-8

import time
from cortexutils.analyzer import Analyzer
import os
import json
import requests
import urllib
import msal
import re

class AzureAlertsAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.scope = [self.get_param('config.scope', None, 'Scope parameter is missing')]
        self.tenant_id = self.get_param('config.tenant_id', None, 'Missing Tenant Id')
        self.application_id = self.get_param('config.application_id', None, 'Missing Application Id')
        self.app_secret = self.get_param('config.app_secret', None, 'Missing App Secret')
        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.authority = "https://login.microsoftonline.com/" + self.tenant_id
        self.data = self.get_param('data', None, 'Missing Data')
    
    def parse_data(self, data):
        if self.service == "getAlertDetails":
            # URL Decode the data
            data = urllib.parse.unquote(data)
            if "protection.office.com" in data or "compliance.microsoft.com" in data:
                # Regex search to isolate the Alert ID from the URL in data
                self.regex_string = ".*([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})"
                self.ticket_id = re.search(self.regex_string, data, re.I).group(1)
                # Build endpoint URL with the extracted Alert ID
                self.endpoint = "https://graph.microsoft.com/v1.0/security/alerts?$filter=Id eq '" + self.ticket_id + "'"
            else:
                self.error("Provided URL is not a recognised Microsoft Security URL.\nAborting AzureAlert Analyzer...")
        elif self.service == "getRiskySignIn":
            self.endpoint = "https://graph.microsoft.com/v1.0/security/alerts?$filter=vendorInformation/provider eq 'IPC' and status eq 'newAlert' and userStates/any(a:a/userPrincipalName eq '" + data + "')"
        else:
            self.error("Unknown service type.\nAborting AzureAlert Analyzer...")

        return self.endpoint

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "AzureAlerts"
        predicate = ""
        value = ""

        if self.service == "getAlertDetails":
            # Set predicate to GetAlertDetails
            predicate = "GetAlertDetails"

            if len(raw["value"]) == 1:
                if raw["value"][0]["status"] == "resolved" or raw["value"][0]["status"] == "dismissed":
                    level = "safe"
                else:
                    level = "suspicious"
                # Set value for short report
                value = "Status: {}".format(raw["value"][0]["status"])
            elif len(raw["value"]) > 1:
                level="suspicious"
                value="Multiple Alerts found"
            else:
                value = "No reports available"
        elif self.service == "getRiskySignIn":
            # Set predicate to GetRiskySignIn
            predicate = "GetRiskySignIn"
            if len(raw["value"]) == 1:
                # Set level of short report based on severity of alert
                if raw["value"][0]["severity"] == "high":
                    level = "malicious"
                elif raw["value"][0]["severity"] == "medium":
                    level = "suspicious"
                else:
                    level = "info"
                # Set value for short report
                value = "Risk Severity: {}".format(raw["value"][0]["severity"])
            elif len(raw["value"]) > 1:
                for self.report in raw["value"]:
                    if self.report["severity"] == "high":
                        level = "malicious"
                    elif self.report["severity"] == "medium" and level != "malicious":
                        level = "suspicious"

                # Set value for short report
                value = "Risk Severity: {}".format(raw["value"][0]["severity"])
            else:
                level = "safe"
                value = "No Risky Sign-in found"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        # Create the app connection to obtain API Token
        if os.path.isfile(self.app_secret):
            self.thumbprint = self.get_param('config.thumbprint', None, 'Missing thumbprint')
            self.app = msal.ConfidentialClientApplication(self.appplication_id, authority=self.authority, client_credential={"thumbprint": self.thumbprint, "private_key": open(self.app_secret).read()})
        else:
            self.app = msal.ConfidentialClientApplication(self.application_id, authority=self.authority, client_credential=self.app_secret)

        # Attempt to get Token if the App connection was succesfull
        if self.app:
            self.result = None

            # Check if we have a valid token in cache
            self.result = self.app.acquire_token_silent(self.scope, account=None)

            # If we don't have a valid token, request one to the App.
            if not self.result:
                self.result = self.app.acquire_token_for_client(scopes=self.scope)
                
            # If we have a Token, launch graph API call
            if "access_token" in self.result:
                # Complete endpoint variable with data passed to Analyzer
                self.endpoint = self.parse_data(self.data)
                # Calling graph using the access token
                self.graph_data = requests.get(self.endpoint, headers={'Authorization': 'Bearer ' + self.result['access_token']}, ).json()
                # Report the result(s)
                self.report(self.graph_data) 
            else:
                self.error("{}: {}".format(self.result.get("error"),self.result.get("error_description")))
        else:
            self.error('Connection to App failed. Please check your parameters')

if __name__ == '__main__':
    AzureAlertsAnalyzer().run()

