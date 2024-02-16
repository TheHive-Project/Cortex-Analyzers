#!/usr/bin/env python3
# encoding: utf-8

import json
import requests
from base64 import b64encode
from cortexutils.analyzer import Analyzer

class SoltraEdge(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        self.base_url = self.get_param("config.base_url", None)
        self.token = self.get_param("config.token", None)
        self.username = self.get_param("config.username", None)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.verify_ssl = self.get_param("config.verify_ssl", True)

        self.headers = {
            "User-Agent": "Cortex 2",
            "Accept": "application/json",
            "Authorization": self.auth_string()
        }


    def auth_string(self):
        '''
        Authenticate based on username and token which is base64-encoded
        '''

        username_token = '{username}:{token}'.format(username=self.username, token=self.token)
        b64encoded_string = b64encode(username_token)
        auth_string = 'Token {b64}'.format(b64=b64encoded_string)

        return auth_string


    def api_overview(self, query):
        '''
        Request to SoltraEdge API
        '''

        url = "{0}/?q={1}&format=json".format(self.base_url, query)
        response = requests.get(url, headers=self.headers, verify=self.verify_ssl)

        if response.status_code == 200:
            return response.json()
        else:
            self.error('Received status code: {0} from Soltra Server. Content:\n{1}'.format(
                response.status_code, response.text)
            )


    def api_related(self, query):
        '''
        Find related objects through SoltraEdge API
        '''

        url = "{0}/{1}/related/?format=json".format(self.base_url, query)
        response = requests.get(url, headers=self.headers, verify=self.verify_ssl)

        if response.status_code == 200:
            return response.json()
        else:
            self.error('Received status code: {0} from Soltra Server. Content:\n{1}'.format(
                response.status_code, response.text)
            )


    def tlp_classifiers(self, name_tlp, val_tlp):
        '''
        Classifier between Cortex and Soltra.
        Soltra uses name-TLP, and Cortex "value-TLP"
        '''

        classifier = {
            "WHITE": 0,
            "GREEN": 1,
            "AMBER": 2,
            "RED": 3
        }

        valid = True

        if classifier[name_tlp] > val_tlp:
            valid = False

        return valid


    def pop_object(self, element):
        '''
        Pop the object element if the object contains an higher TLP then allowed.
        '''

        redacted_text = "Redacted. Object contained TLP value higher than allowed."

        element['id'] = ''
        element['url'] = ''
        element['type'] = ''
        element['tags'] = []
        element['etlp'] = None
        element['title'] = redacted_text
        element['tlpColor'] = element['tlpColor']
        element['uploaded_on'] = ''
        element['uploaded_by'] = ''
        element['description'] = redacted_text
        element['children_types'] = []

        element['summary']['type'] = ''
        element['summary']['value'] = ''
        element['summary']['title'] = redacted_text
        element['summary']['description'] = redacted_text

        return element


    def run(self):

        result = {}
        content = self.getData()

        if self.service == "search":
            self.predicate = "Search"
            self.level = "suspicious"

            response = self.api_overview(content)

            for obj in response['hits']:
                name_tlp = obj['tlpColor'].upper()
                if not self.tlp_classifiers(name_tlp, self.tlp):
                    self.pop_object(obj)
                else:
                    # Add object relations if found
                    obj['object_related'] = self.api_related(obj['id'])

        else:
            # Did not match any services
            self.error("Invalid service")

        self.response = response
        
        result["findings"] = response
        result["findings"]['soltra_host'] = self.base_url.split("/api/stix")[0]

        return self.report(result)


    def summary(self, raw_report):

        return {
            "estimate": self.response["estimate"],
            "took": self.response["took"],
            "taxonomies": [{
                "namespace": "Soltra",
                "predicate": self.predicate,
                "value": self.response['estimate'],
                "level": self.level
            }]
        }



if __name__ == '__main__':
    SoltraEdge().run()
