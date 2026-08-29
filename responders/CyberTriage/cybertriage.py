#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from cortexutils.responder import Responder
from requests.exceptions import RequestException
import requests
import ipaddress
import json

requests.packages.urllib3.disable_warnings()

class CyberTriage(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.ct_server = self.get_param('config.ct_server', '127.0.0.1')
        self.ct_port = self.get_param('config.ct_port', '9443')
        self.ct_username = self.get_param(
            'config.ct_username', None,
            'Missing investigation username')
        self.ct_password = self.get_param(
            'config.ct_password', None,
            'Missing investigation user password')
        self.ct_upload_hash = self.get_param('config.ct_upload_hash', True)
        self.ct_upload_file = self.get_param('config.ct_upload_file', False)
        self.__req_headers = {
            'Content-Type': 'application/json',
            'restApiKey': self.get_param(
                'config.ct_api_key', None,
                'Missing CyberTriage API Key')
        }
        self.__verify_server_cert = False
        self.ct_sid = None

    def check_credentials(self):
        try:
            _r = requests.get(
                'https://{0}:{1}/api/correlation/checkcredentials'.format(
                    self.ct_server, self.ct_port
                    ),
                headers=self.__req_headers,
                verify=self.__verify_server_cert
                )
            if _r.status_code == 200:
                return True
            else:
                self.error("API Request failed: {}".format(_r.text))
        except RequestException as e:
            self.error("Failed to make requests due to {}".format(e.strerror))

    def triage_endpoint(self, endpoint, incident_name):
        # Make data dict for rest call
        json_data = {
            'incidentName': incident_name,
            'hostName': endpoint,
            'userId': self.ct_username,
            'password': self.ct_password,
            'scanOptions': ",".join([
                'pr', 'nw', 'nc', 'st', 'sc',
                'ru', 'co', 'lo', 'ns', 'wb', 'fs'
                ]),
            'malwareScanRequested': self.ct_upload_hash,
            'sendContent': self.ct_upload_file,
            'sendIpAddress': False
        }

        try:
            _r = requests.post(
                'https://{0}:{1}/api/livesessions'.format(
                    self.ct_server, self.ct_port
                    ),
                json=json_data,
                headers=self.__req_headers,
                verify=self.__verify_server_cert
            )
            if _r.status_code == 202: # 202 accepted is returned on successful submission
                self.ct_sid = _r.json()["SessionId"]
            else:
                self.error("API Requests failed {}: {}".format(_r.status_code, _r.text))
        except RequestException as e:
            self.error("Failed to make requests due to {}".format(e.strerror))

    def run(self):
        Responder.run(self)

        if self.get_param("data.dataType") in ["ip"]:
            endpoint = self.get_param("data.data")
        else:
            self.error('Invalid datatype {}'.format(self.get_param("data.dataType")))
        
        caseId = self.get_param("data.case.caseId")

        if ipaddress.IPv4Address(endpoint).is_private:
            if self.check_credentials():
                self.triage_endpoint(endpoint=endpoint, incident_name=caseId)
                self.report({'message': 'Endpoint {} under investigation. Incident Name: {}, Session ID: {}'.format(endpoint, caseId, self.ct_sid)})
        else:
            self.error('IP Address {0} is out of scope'.format(endpoint))

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='CyberTriage:Investigated')]


if __name__ == '__main__':
    CyberTriage().run()
