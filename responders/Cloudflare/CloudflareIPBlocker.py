#!/usr/bin/env python3
# encoding: utf-8
# Author: Nick Babkin @nickbabkin
import requests
import traceback
import datetime
import os
from cortexutils.responder import Responder

# Initialize Cloudflare Responder Class
class CloudflareIPBlocker(Responder):
    
    def __init__(self):
        Responder.__init__(self)
        self.cloudflare_api_key = self.get_param('config.cloudflare_api_key', None, 'Cloudflare API Key')
        self.cloudflare_account_ids = self.get_param('config.cloudflare_account_ids', [], 'Cloudflare Account ID')
        self.cloudflare_action = self.get_param('config.cloudflare_action', [], 'Cloudflare Action')
        self.time = ''
        self.dataType = self.get_param('data.dataType')

    def run(self):
        try:
            if self.dataType== "ip":
                self.ip_address = self.get_param('data.data', None, 'No IP Address supplied')
            else:
                self.error("No IP Address supplied")
            
            # Build the request payload to block the IP address
            payload = {
                "mode": self.cloudflare_action,
                "configuration": {
                    "target": "ip",
                    "value": self.ip_address,
                },
                "notes": "Blocked by Hive responder. Case number {}".format(self.get_param('data.case.caseId', None, 'No CaseID Fetched'))
            }      
            
            # Make the API request to Cloudflare
            for account_id in self.cloudflare_account_ids:
                url = "https://api.cloudflare.com/client/v4/accounts/{}/firewall/access_rules/rules".format(account_id)
                headers = {
                    "Authorization": "Bearer {}".format(self.cloudflare_api_key),
                    "Content-Type": "application/json"
                }
                response = requests.post(url, headers=headers, json=payload)

                # Checking for errors
                if response.status_code != 200:
                    self.error('Request failed with the following status: {}'.format(response.status_code))
                
                else:
                    #record time
                    self.time = datetime.datetime.utcnow()
        
        except Exception as ex:
            self.error(traceback.format_exc())
        # Build report to return to Cortex
        full_report = {"message": "IP Address {} successfully blocked at {}".format(self.ip_address, self.time)}
        self.report(full_report)
        
    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='Cloudflare:Blocked')]


if __name__ == '__main__':
    CloudflareIPBlocker().run()
