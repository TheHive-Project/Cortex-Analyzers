#!/usr/bin/env python
# encoding: utf-8

from cortexutils.analyzer import Analyzer

import os.path
import requests
import time


class JoeSandboxAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'JoeSandbox service is missing')
        self.url = self.get_param('config.url', None, 'JoeSandbox url is missing')
        if self.get_param('config.key'):
            self.apikey = self.get_param('config.key')
        else:
            self.apikey = self.get_param('config.apikey', None, 'JoeSandbox API key is missing')
        self.analysistimeout = self.get_param('config.analysistimeout', 30*60, None)
        self.networktimeout = self.get_param('config.networktimeout', 30, None)

    def summary(self, raw):
        result = {
            'service': self.service,
            'dataType': self.data_type
        }

        taxonomies = []
        namespace = "JSB"
        predicate = "Report"

        r = raw['detection']

        value = "\"{}/{}\"".format(r["score"], r["maxscore"])

        if r["clean"]:
            level = "safe"
        elif r["suspicious"]:
            level = "suspicious"
        elif r["malicious"]:
            level = "malicious"
        else:
            level = "info"
            value = "Unknown"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        result.update({"taxonomies":taxonomies})

        return result

    def runv1(self):
        data = {
            'apikey': self.apikey,
            'tandc': 1,
            'auto': 1,
            'comments': 'Submitted by Cortex'
        }
        files = {}

        # file analysis with internet access
        if self.service == 'file_analysis_inet':
            extension = os.path.splitext(self.get_param('filename', ''))[1]
            filepath = self.get_param('file', None, 'File is missing')
            files['sample'] = (filepath + extension, open(filepath, 'rb'))
            data['type'] = 'file'
            data['inet'] = 1

        # file analysis without internet access
        elif self.service == 'file_analysis_noinet':
            extension = os.path.splitext(self.get_param('filename', ''))[1]
            filepath = self.get_param('file', None, 'File is missing')
            files['sample'] = (filepath + extension, open(filepath, 'rb'))
            data['type'] = 'file'
            data['inet'] = 0

        # url analysis
        elif self.service == 'url_analysis':
            data['url'] = self.get_data()
            data['type'] = 'url'
            data['inet'] = 1

        else:
            self.error('Unknown JoeSandbox service')

        # Submit the file/url for analysis
        response = requests.post(self.url + 'api/analysis', files=files, data=data, timeout=self.networktimeout)
        webid = response.json()['webid']

        # Wait for the analysis to finish
        data = {
            'apikey': self.apikey,
            'webid': webid
        }
        finished = False
        tries = 0
        while not finished and tries <= self.analysistimeout/60:
            time.sleep(60)
            response = requests.post(self.url + 'api/analysis/check', data=data, timeout=self.networktimeout)
            content = response.json()
            if content['status'] == 'finished':
                finished = True
            tries += 1
        if not finished:
            self.error('JoeSandbox analysis timed out')

        # Download the report
        data = {
            'apikey': self.apikey,
            'webid': webid,
            'type': 'irjsonfixed',
            'run': 0
        }
        response = requests.post(self.url + 'api/analysis/download', data=data, timeout=self.networktimeout)
        analysis = response.json()['analysis']
        analysis['htmlreport'] = self.url + 'analysis/' + str(analysis['id']) + '/0/html'
        analysis['pdfreport'] = self.url + 'analysis/' + str(analysis['id']) + '/0/pdf'
        self.report(analysis)

    def runv2(self):
        data = {
            'apikey': self.apikey,
            'accept-tac': '1',
            'systems': None,
            'comments': 'Submitted by Cortex'
        }
        files = {}

        # file analysis with internet access
        if self.service == 'file_analysis_inet':
            extension = os.path.splitext(self.get_param('filename', ''))[1]
            filepath = self.get_param('file', None, 'File is missing')
            files['sample'] = (filepath + extension, open(filepath, 'rb'))
            data['internet-access'] = '1'

        # file analysis without internet access
        elif self.service == 'file_analysis_noinet':
            extension = os.path.splitext(self.get_param('filename', ''))[1]
            filepath = self.get_param('file', None, 'File is missing')
            files['sample'] = (filepath + extension, open(filepath, 'rb'))
            data['internet-access'] = '0'

        # url analysis
        elif self.service == 'url_analysis':
            data['url'] = self.get_data()
            data['internet-access'] = '1'

        else:
            self.error('Unknown JoeSandbox service')

        # Submit the file/url for analysis
        response = requests.post(self.url + 'api/v2/analysis/submit', files=files, data=data, timeout=self.networktimeout)
        webid = response.json()['data']['webids'][0]

        # Wait for the analysis to finish
        data = {
            'apikey': self.apikey,
            'webid': webid
        }
        finished = False
        tries = 0
        while not finished and tries <= self.analysistimeout/60:
            time.sleep(60)
            response = requests.post(self.url + 'api/v2/analysis/info', data=data, timeout=self.networktimeout)
            content = response.json()
            if content['data']['status'] == 'finished':
                finished = True
            tries += 1
        if not finished:
            self.error('JoeSandbox analysis timed out')

        # Download the report
        data = {
            'apikey': self.apikey,
            'webid': webid,
            'type': 'irjsonfixed',
            'run': 0
        }
        response = requests.post(self.url + 'api/v2/analysis/download', data=data, timeout=self.networktimeout)
        analysis = response.json()['analysis']
        analysis['htmlreport'] = self.url + 'analysis/' + str(analysis['id']) + '/0/html'
        analysis['pdfreport'] = self.url + 'analysis/' + str(analysis['id']) + '/0/pdf'
        self.report(analysis)

    def run(self):
        Analyzer.run(self)

        try:
            data = {
                'apikey': self.apikey
            }
            # Check whether API v2 is supported or not
            response = requests.post(self.url + 'api/v2/server/online', data=data, timeout=self.networktimeout, allow_redirects=False)
            if response.status_code == 200:
                self.runv2()
            else:
                self.runv1()

        except Exception as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    JoeSandboxAnalyzer().run()
