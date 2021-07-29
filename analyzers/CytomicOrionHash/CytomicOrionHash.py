#!/usr/bin/env python3
# -*- coding: utf-8 -*

import requests
import json
from requests.auth import HTTPBasicAuth
from cortexutils.analyzer import Analyzer

class CytomicOrionHash(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.client_id = self.get_param(
            'config.client_id', None, 'The Client ID is missing')
        self.client_secret = self.get_param(
            'config.client_secret', None, 'The Client Secret is missing')
        self.password = self.get_param(
            'config.password', None, 'The password is missing')
        self.username = self.get_param(
            'config.username', None, 'The username is missing')

    @property
    def auth(self):
        return HTTPBasicAuth(
            self.client_id,
            self.client_secret
        )

    @property
    def body(self):
        return {
            'username': self.username,
            'password': self.password,
            'scope': 'orion.api',
            'grant_type': 'password'
        }

    @property
    def headers(self):
        return {
            'Content-Type': 'application/x-www-form-urlencoded',
        }

    @property
    def token(self):
        r = requests.post(
            'https://auth.pandasecurity.com/oauth/token',
            auth=self.auth,
            headers=self.headers,
            data=self.body,
            verify=False
        )
        if r.status_code == 200:
            return r.json()
        else:
            self.error(
                f"Unable to get panda token - {str(r.content)}")
            return None

    def run(self):
        Analyzer.run(self)

        data = self.get_param('data', None, 'Data is missing')

        if self.data_type != 'hash':
            self.error('Invalid data type')
        
        if len(data) == 32:
            token = self.token
            if token is not None:
                url_md5_info = f'https://api.orion.cytomic.ai/api/v1/applications/forensics/md5/{data}/info'
                r = requests.get(
                    url_md5_info, 
                    headers={
                        'Authorization': f"Bearer {token['access_token']}",
                        'Accept': 'application/json'
                    }, 
                    verify=False
                    )
                if r.status_code == 200:
                    self.report(r.json())
                else:
                    self.error(f"Could not get hash {data}")

            else:
                self.error("Unable to get panda token")
        else:
            self.error('Invalid hash only MD5 is accepted')

    def summary(self, raw):
        
        taxonomies = []

        if raw.get('fileName', None) is not None \
            and raw.get('fileName', None) != 'null':
            if raw.get('fileName', None) is not None \
                and len(raw.get('fileName', None)) == 0:
                taxonomies.append(self.build_taxonomy("info", "fileName", "fileName", 'Hash Not Found'))
            else:
                taxonomies.append(self.build_taxonomy("info", "fileName", "fileName", raw['fileName']))

        if raw.get('lastSeen', None) is not None \
            and raw.get('lastSeen', None) != 'null':
            taxonomies.append(self.build_taxonomy("info", "lastSeen", "lastSeen", raw['lastSeen']))
        
        if raw.get('firstSeen', None) is not None \
            and raw.get('firstSeen', None) != 'null':
            taxonomies.append(self.build_taxonomy("info", "firstSeen", "firstSeen", raw['firstSeen']))

        if raw.get('classificationName', None) is not None \
            and raw.get('classificationName', None) != 'null':
            taxonomies.append(self.build_taxonomy("high", "classificationName", "classificationName", raw['classificationName']))

        
        return {"taxonomies": taxonomies}


if __name__ == '__main__':
    CytomicOrionHash().run()
