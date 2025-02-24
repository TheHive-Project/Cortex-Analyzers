#!/usr/bin/env python3
# encoding: utf-8
# Author: Daniel Weiner @dmweiner; revised by @jahamilto; nusantara-self, StrangeBee
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
        self.service = self.get_param('config.service', None)

    def authenticate(self):
        token_data = {
            "grant_type": "client_credentials",
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }
        
        redirect_uri = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        token_r = requests.post(redirect_uri, data=token_data)
        
        if token_r.status_code != 200:
            self.error(f'Failure to obtain Azure access token: {token_r.content}')
        
        return token_r.json().get('access_token')

    def check_user_status(self, user, headers, base_url):
        r = requests.get(f"{base_url}{user}?$select=accountEnabled", headers=headers)

        if r.status_code == 404:
            self.error(f'User {user} not found in Microsoft Entra ID')
            return None
        elif r.status_code != 200:
            try:
                error_message = r.json().get("error", {}).get("message", "Unknown error")
            except ValueError:
                error_message = "Invalid response received from API"
            self.error(f'Failure to retrieve user status for {user}: {error_message}')
            return None

        try:
            user_data = r.json()
            return user_data.get("accountEnabled", None)
        except ValueError:
            self.error("Invalid JSON response received")
            return None


    def run(self):
        Responder.run(self)
        token = self.authenticate()
        headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
        base_url = 'https://graph.microsoft.com/v1.0/users/'
        
        if self.service == "tokenRevoker":
            if self.get_param('data.dataType') == 'mail':
                try:
                    self.user = self.get_param('data.data', None, 'No UPN supplied to revoke credentials for')
                    if not self.user:
                        self.error("No user supplied")
                    
                    r = requests.post(f"{base_url}{self.user}/revokeSignInSessions", headers=headers)
                    
                    if r.status_code != 200:
                        self.error(f'Failure to revoke access tokens of user {self.user}: {r.content}')
                    else:
                        self.time = datetime.datetime.utcnow()
                except Exception:
                    self.error(traceback.format_exc())
                
                full_report = {"message": f"User {self.user} authentication tokens successfully revoked at {self.time}"}
                self.report(full_report)
            else:
                self.error('Incorrect dataType. "mail" expected.')
        
        elif self.service == "forcePasswordReset":
            if self.get_param('data.dataType') == 'mail':
                try:
                    self.user = self.get_param('data.data', None, 'No UPN supplied for password reset')
                    if not self.user:
                        self.error("No user supplied")
                    
                    data = {"passwordProfile": {"forceChangePasswordNextSignIn": True}}
                    r = requests.patch(f"{base_url}{self.user}", headers=headers, json=data)
                    
                    if r.status_code != 204:
                        self.error(f'Failure to reset password for user {self.user}: {r.content}')
                    
                    self.report({"message": f"Password reset initiated for user {self.user}, user will be prompted to change it at next sign-in"})
                except Exception:
                    self.error(traceback.format_exc())
            else:
                self.error('Incorrect dataType. "mail" expected.')
        
        elif self.service == "forcePasswordResetWithMFA":
            try:
                self.user = self.get_param('data.data', None, 'No UPN supplied for password reset with MFA')
                if not self.user:
                    self.error("No user supplied")
                
                data = {"passwordProfile": {"forceChangePasswordNextSignIn": True, "forceChangePasswordNextSignInWithMfa": True}}
                r = requests.patch(f"{base_url}{self.user}", headers=headers, json=data)
                
                if r.status_code != 204:
                    self.error(f'Failure to reset password with MFA for user {self.user}: {r.content}')
                
                self.report({"message": f"Password reset initiated for user {self.user}, user will be prompted for MFA and password change at next sign-in"})
            except Exception:
                self.error(traceback.format_exc())
                       
        elif self.service == "enableUser":
            if self.get_param('data.dataType') == 'mail':
                try:
                    self.user = self.get_param('data.data', None, 'No UPN supplied to enable user')
                    if not self.user:
                        self.error("No user supplied")
                    
                    user_status = self.check_user_status(self.user, headers, base_url)
                    if user_status is True:
                        self.report({"message": f"User {self.user} is already enabled"})
                        return
    
                    data = {"accountEnabled": True}
                    r = requests.patch(f"{base_url}{self.user}", headers=headers, json=data)
                    
                    if r.status_code != 204:
                        self.error(f'Failure to enable user {self.user}: {r.content}')
                    
                    self.report({"message": f"User {self.user} has been enabled"})
                except Exception:
                    self.error(traceback.format_exc())
            else:
                self.error('Incorrect dataType. "mail" expected.')

        
        elif self.service == "disableUser":
            if self.get_param('data.dataType') == 'mail':
                try:
                    self.user = self.get_param('data.data', None, 'No UPN supplied to disable user')
                    if not self.user:
                        self.error("No user supplied")
                    
                    user_status = self.check_user_status(self.user, headers, base_url)
                    if user_status is False:
                        self.report({"message": f"User {self.user} is already disabled"})
                        return
                    
                    data = {"accountEnabled": False}
                    r = requests.patch(f"{base_url}{self.user}", headers=headers, json=data)
                    
                    if r.status_code != 204:
                        self.error(f'Failure to disable user {self.user}: {r.content}')
                    
                    self.report({"message": f"User {self.user} has been disabled"})
                except Exception:
                    self.error(traceback.format_exc())
            else:
                self.error('Incorrect dataType. "mail" expected.')
        
        else:
            self.error({'message': "Unidentified service"})

if __name__ == '__main__':
    MSEntraID().run()
