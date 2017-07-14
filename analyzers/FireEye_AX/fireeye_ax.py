#!/usr/bin/env python
# encoding: utf-8

import json
import requests
import ast
from requests.auth import HTTPBasicAuth
from cortexutils.analyzer import Analyzer
import xml.etree.ElementTree as ET
import time
from cStringIO import StringIO

class FireEyeAX(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam(
            'config.service', None, 'Service parameter is missing')
        self.username = self.getParam(
            'config.username', None, 'Missing FireEye AX username')
        self.password = self.getParam(
            'config.password', None, 'Missing FireEye AX password')
        self.url = self.getParam(
            'config.url', None, 'Missing FireEye URL')
        self.AuthToken = None
        self.sandbox_options = self.getParam(
            'config.sandbox_options', None, 'Sandbox options parameter is missing')

    def getAuthToken(self):
        url = self.url + "auth/login"
        auth = HTTPBasicAuth(self.username, self.password)
        try:
            request = requests.post(url=url, auth=auth, verify=False)
            if request.status_code == 200:
                self.AuthToken = request.headers['X-FeApi-Token']
            else:
                self.error("FireEye AX: Unable to retrieve token - status code is " + str(request.status_code))
        except Exception as e:
            self.unexpectedError(e)


    def get_sandbox_report(self, scan_id):
        url = self.url + 'submissions/results/{0}?info_level=extended'.format(scan_id)
        headers = {'X-FeApi-Token': str(self.AuthToken), 'Accept':'application/json'}
        results_json = None
        try:
            request = requests.get(url=url, headers=headers, verify=False)
            if request.status_code == 200:
                results_json = json.loads(request.content)
            else:
                self.error("FireEye AX: File submitted, but unable to retrieve Sandbox results of file \n" + request.content)
        except Exception as e:
            self.unexpectedError(e)

        if results_json is not None:
            if "origid" in results_json['alert'][0]["explanation"]["malwareDetected"]["malware"][0]:
                origid = results_json['alert'][0]["explanation"]["malwareDetected"]["malware"][0]['origid']
                results_json = self.get_sandbox_report(origid)
            return results_json
        else:
            self.error("FireEye AX: Unable to retrieve FireEye Sandbox report")


    def get_results(self,scan_id):
        status = self.get_status(scan_id)
        if status == 1:
            sandbox_report = self.get_sandbox_report(scan_id)
            self.report({'fireeye_ax': sandbox_report})
        else:
            time.sleep(10)
            self.get_results(scan_id)

    def summary(self, raw):
        result = {
            'service': self.service,
            'dataType': self.data_type
        }

        taxonomies = []
        namespace = "FireEye"
        predicate = "Report"

        severity = raw['fireeye_ax']['alert'][0]['severity']

        if severity == "MINR":
            level = "safe"
            value = "MINOR"
        elif severity == "MAJR":
            level = "malicious"
            value = "MAJOR"
        elif severity == "CRITICAL":
            level = "malicious"
            value = "CRITICAL"
        else:
            level = "info"
            value = "Unknown"

        taxonomies.append(self.build_taxonomy(level=level, namespace=namespace, predicate=predicate, value=value))
        result.update({"taxonomies":taxonomies})

        return result

    def get_status(self, scan_id):
        url = self.url + 'submissions/status/{0}'.format(scan_id)
        headers = {'X-FeApi-Token': str(self.AuthToken), 'Accept':'application/xml'}
        try:
            request = requests.get(url=url, headers=headers, verify=False)
            if request.status_code == 200:
                submission_status = ""
                status_xml = ET.parse(StringIO(request.content))
                for child_submission_status in status_xml.getroot():
                    submission_status = child_submission_status.text
                if submission_status == "Done":
                    scan_finished = 1
                else:
                    scan_finished = 0
                return scan_finished
            else:
                self.error("FireEye AX: File submitted, but unable to retrieve status of file \n" + request.content)
        except Exception as e:
            self.unexpectedError(e)

    def submit_file(self, filename, filepath):
        url = self.url + 'submissions'
        json_sandbox_options = json.dumps(self.sandbox_options)

        if filename and filepath:
            files = [
                        ('filename', (filename, open(filepath, 'rb'), 'application/octet-stream')),
                        ('options', (None, json_sandbox_options, 'application/json'))
                    ]

            try:
                request = requests.post(url=url, headers={'X-FeApi-Token' : self.AuthToken}, files=files, verify=False)
                scan_id = ast.literal_eval(request.content)[0]["ID"]
                self.get_results(scan_id=scan_id)
            except Exception as e:
                self.error("FireEye AX: Unable to submit file to FireEye AX" + str(e))
        else:
            self.error("FireEye AX: Unable to submit file to FireEye AX as filename/filepath is not valid or empty")



    def logout(self):
        url = self.url + 'auth/logout'
        try:
            request = requests.post(url=url, headers={'X-FeApi-Token':self.AuthToken}, verify=False)
        except Exception as e:
            self.unexpectedError(e)

    def run(self):
        Analyzer.run(self)
        if self.AuthToken is None:
            self.getAuthToken()
        if self.service == "scan":
            if self.data_type == 'file':
                filename = self.getParam('attachment.name', 'noname.ext')
                filepath = self.getParam('file', None, 'File is missing')
                self.submit_file(filename, filepath)
            else:
                self.error('Invalid data type')
        else:
            self.notSupported()

        self.logout()



if __name__ == '__main__':
    FireEyeAX().run()