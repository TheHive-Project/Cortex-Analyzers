import json
import requests
import cortexutils
import traceback
import datetime
# Process json inputs

from cortexutils.responder import Responder

# Initialize Azure Class
class AzureTokenRevoker(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.client_id = self.get_params('config.client_id', None, 'Azure AD Application ID/Client ID Missing')
        self.client_secret = self.get_params('config.client_secret', None, 'Azure AD Registered Application Client Secret Missing')
        self.redirect_uri = self.get_params('config.redirect_uri', None, 'Set a redirect URI in Azure AD Registered Application. (ex. https://logon.microsoftonline.<tenant id>/oauth2/token)')
        self.user = self.get_params('user', None, 'No UPN supplied to revoke credentials for')
        self.time = ''
    def run(self):
        try:
            base_resource = "https://graph.microsoft.com"

            token_data = {
                "grant_type": "client_credentials",
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'resource': 'https://graph.microsoft.com',
                'scope': 'https://graph.microsoft.com'
                }


            #Authenticate to the graph api 

            token_r = requests.post(self.redirect_uri, data=token_data)
            token = token_r.json().get('access_token')

            if token_r.status_code != 200:
                self.error('Failure to obtain azure access token: {}'.format(token_r.content))

            # Set headers for future requests
            headers = {
                'Authorization': 'Bearer {}'.format(token)
            }

            base_url = 'https://graph.microsoft.com/v1.0/'
            
            r = requests.post(base_url + 'users/{}/revokeSignInSessions'.format(user), headers=headers)

            if r.status_code != 200:
                self.error('Failure to revoke access tokens of user {}: {}'.format(user, r.content))
            
            else:
                #record time of successful auth token revokation
                self.time = datetime.datetime.now()
        
        except Exception as ex:
            self.error(traceback.format_exc())

    def operations(self, raw):
        #Needs to be changed
        return [self.build_operation('AddTagToArtifact', tag='AzureAD:UserAADAuthTokensReset{}'.format(self.time))]

if __name__ == '__main__':
    AzureTokenRevoker().run()