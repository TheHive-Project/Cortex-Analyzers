#!/usr/bin/env python3
from cortexutils.responder import Responder
import requests
import json
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseObservable

class AWX(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.url = self.get_param("config.url", "")
        self.username = self.get_param("config.username","")
        self.password = self.get_param("config.password","")
        self.workflow_id = self.get_param("config.workflow_id", "")
        self.observable_all = self.get_param('data', None, 'Data missing!')
        self.cert_path = self.get_param('config.cert_path')

    def run(self):
        Responder.run(self)
        headers = {
            'Content-Type': 'application/json'
        }
        payload = {
            'extra_vars': json.dumps(self.observable_all)
        }
        print("start awx job")
        # Start the job
        job_start_endpoint = self.url + '/api/v2/job_templates/' + self.workflow_id + '/launch/'

        if self.cert_path == '':
            response = requests.post(job_start_endpoint, headers=headers, auth=(self.username, self.password), data=json.dumps(payload))
        else:
            response = requests.post(job_start_endpoint, headers=headers, auth=(self.username, self.password), data=json.dumps(payload), verify=self.cert_path)

        # Check the response status
        if response.status_code == 201:
            print("success")
            self.report({"Message": "Executed workflow"})
        else:
            print("error")
            self.error(response.status_code)

if __name__ == '__main__':
    AWX().run()
