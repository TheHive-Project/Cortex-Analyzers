#!/usr/bin/env python
# encoding: utf-8

from cortexutils.analyzer import Analyzer

import requests
import time
from os.path import basename

class CuckooSandboxAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam('config.service', None, 'CuckooSandbox service is missing')
        self.url = self.getParam('config.url', None, 'CuckooSandbox url is missing')
        #self.analysistimeout = self.getParam('config.analysistimeout', 30*60, None)
        #self.networktimeout = self.getParam('config.networktimeout', 30, None)

    def summary(self, raw):
        result = {
            'service': self.service,
            'dataType': self.data_type
        }

        result.update(raw['info'])

        return result

    def run(self):
        Analyzer.run(self)

        try:

            # file analysis
            if self.service in ['file_analysis_inet', 'file_analysis_noinet']:
                filepath = self.getParam('file', None, 'File is missing')
		filename = basename(filepath)
                with open(filepath, "rb") as sample:
                    files = {"file": (filename, sample)}
                    response = requests.post(self.url + 'tasks/create/file', files=files)
                task_id = response.json()['task_ids'][0]

            # url analysis
            elif self.service == 'url_analysis':
                data = {"url": self.getData()}
                response = requests.post(self.url + 'tasks/create/url', data=data)
                task_id = response.json()['task_id']

            else:
                self.error('Unknown CuckooSandbox service')

            finished = False
            tries = 0
            while not finished and tries <= 15: # 5 minuti di tentativo
                time.sleep(120)
                response = requests.get(self.url + 'tasks/view/' + str(task_id))
                content = response.json()['task']['status']
                if content == 'reported':
                    finished = True
                tries += 1
            if not finished:
                self.error('CuckooSandbox analysis timed out')

            # Download the report
            response = requests.get(self.url + 'tasks/report/' + str(task_id) + '/json')
            #analysis['htmlrepoon()t'] = self.url + 'analysis/' + str(task_id) 
            #analysis['pdfreport'] = self.url + 'filereport/' + str(analysis['id']) + '/0/pdf'
            list_description = [x['description'] for x in response.json()['signatures']]
            suri_alerts = [(x['signature'],x['dstip'],x['dstport'],x['severity']) for x in response.json()['suricata']['alerts']]
            self.report({'malscore': response.json()['malscore'], 'signatures': list_description, 'suricata_alerts': suri_alerts})

	except requests.exceptions.RequestException as e:
            self.error(e)

        except Exception as e:
            self.unexpectedError(e)

if __name__ == '__main__':
    CuckooSandboxAnalyzer().run()
