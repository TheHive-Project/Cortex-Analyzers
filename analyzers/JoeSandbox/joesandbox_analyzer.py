#!/usr/bin/env python
# encoding: utf-8

from cortexutils.analyzer import Analyzer

import requests
import time

class JoeSandboxAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'JoeSandbox service is missing')
        self.url = self.get_param('config.url', None, 'JoeSandbox url is missing')
        # self.apikey = self.get_param('config.key', None, 'JoeSandbox apikey is missing')
        if self.get_param('config.key'):
            self.apikey = self.get_param('config.key')
        else:
            self.apikey = self.get_param('config.apikey', None, 'MISP key for API is missing')
        self.analysistimeout = self.get_param('config.analysistimeout', 30*60, None)
        self.networktimeout = self.get_param('config.networktimeout', 30, None)

    def summary(self, raw):
        result = {
            'service': self.service,
            'dataType': self.data_type
        }

        taxonomies = []
        level = "info"
        namespace = "JSB"
        predicate = "Report"
        value = "\"Clean\""


        r = raw['detection']

        taxonomy["value"] = "\"{}/{}\"".format(r["score"], r["maxscore"])
        if r["clean"]:
            level = "safe"
        elif r["suspicious"]:
            level = "suspicious"
            value = "Suspicious"
        elif r["malicious"]:
            level = "malicious"
            value = "Malicious"


        else:
            level = "info"
            value = "Unknown"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        result.update({"taxonomies":taxonomies})

        return result

    def run(self):
        Analyzer.run(self)

        try:
            data = {
                'apikey': self.apikey,
                'tandc': 1,
                'auto': 1,
                'comments': 'Submitted by Cortex'
            }
            files = {}

            # file analysis with internet access
            if self.service == 'file_analysis_inet':
                filepath = self.get_param('file', None, 'File is missing')
                files['sample'] = open(filepath, 'rb')
                data['type'] = 'file'
                data['inet'] = 1

            # file analysis without internet access
            elif self.service == 'file_analysis_noinet':
                filepath = self.get_param('file', None, 'File is missing')
                files['sample'] = open(filepath, 'rb')
                data['type'] = 'file'
                data['inet'] = 0

            # url analysis
            elif self.service == 'url_analysis':
                data['url'] = self.getData()
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

        except Exception as e:
            self.unexpectedError(e)

if __name__ == '__main__':
    JoeSandboxAnalyzer().run()
