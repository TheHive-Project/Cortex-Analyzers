#!/usr/bin/env python3
# encoding: utf-8
# Author: Daniel Weiner @dmweiner, revised by @jahamilto
import requests
import traceback
import datetime
from cortexutils.responder import Responder

# Initialize Azure Class
class MSEntraID(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.client_id = self.get_param('config.client_id', None, 'Microsoft Entra ID Application ID/Client ID Missing')
        self.client_secret = self.get_param('config.client_secret', None, 'Microsoft Entra ID Registered Application Client Secret Missing')
        self.tenant_id = self.get_param('config.tenant_id', None, 'Microsoft Entra ID Tenant ID Mising')
        self.time = ''
    def run(self):
        Responder.run(self)

        if self.get_param('data.dataType') == 'mail':
            try:
                self.user = self.get_param('data.data', None, 'No UPN supplied to revoke credentials for')
                if not self.user:
                    self.error("No user supplied")

                token_data = {
                    "grant_type": "client_credentials",
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'resource': 'https://graph.microsoft.com',
                    'scope': 'https://graph.microsoft.com'
                    }


                #Authenticate to the graph api 

                redirect_uri = "https://login.microsoftonline.com/{}/oauth2/token".format(self.tenant_id)
                token_r = requests.post(redirect_uri, data=token_data)
                token = token_r.json().get('access_token')

                if token_r.status_code != 200:
                    self.error('Failure to obtain azure access token: {}'.format(token_r.content))

                # Set headers for future requests
                headers = {
                    'Authorization': 'Bearer {}'.format(token)
                }

                base_url = 'https://graph.microsoft.com/v1.0/'
                
                r = requests.post(base_url + 'users/{}/revokeSignInSessions'.format(self.user), headers=headers)

                if r.status_code != 200:
                    self.error('Failure to revoke access tokens of user {}: {}'.format(self.user, r.content))
                
                else:
                    #record time of successful auth token revokation
                    self.time = datetime.datetime.utcnow()
            
            except Exception as ex:
                self.error(traceback.format_exc())
            # Build report to return to Cortex
            full_report = {"message": "User {} authentication tokens successfully revoked at {}".format(self.user, self.time)}
            self.report(full_report)
        else:
            self.error('Incorrect dataType. "mail" expected.')


if __name__ == '__main__':
    MSEntraID().run()
