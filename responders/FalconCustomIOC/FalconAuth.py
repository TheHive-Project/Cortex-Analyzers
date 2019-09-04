import time
import json
import requests


class FalconAuth:
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret
        with open("/tmp/OAuth2.json", "w+") as f:
            f.write("")

    def newtoken(self):
        response = requests.post("https://api.crowdstrike.com/oauth2/token", data={"client_id": self.client_id, "client_secret": self.client_secret},
                                 headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
        if not response.status_code == 201:
            return None
        json_data = response.json()
        json_data["expires"] = time.time()+json_data["expires_in"]
        return json_data

    def getToken(self):
        tokendata = ''
        with open("/tmp/OAuth2.json", "r") as f:
            try:
                tokendata = json.loads(f.read())
                if tokendata['expires'] < time.time()+1.0:
                    tokendata = self.newtoken()
            except Exception:
                tokendata = self.newtoken()
        with open("/tmp/OAuth2.json", "w+") as f:
            f.write(json.dumps(tokendata))
            return tokendata['access_token']
