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
        taxonomies = []
        level = "safe"
        namespace = "CSB"
        predicate = "Malscore"
        value = "\"0\""

        result = {
            'service': self.service,
            'dataType': self.data_type
        }
        result["malscore"] = raw.get("malscore", None)
        result["malfamily"] = raw.get("malfamily", None)

        if result["malscore"] > 6.5:
            level = "malicious"
        elif result["malscore"] > 2:
            level = "suspicious"
        elif result["malscore"] > 0:
            level = "safe"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, result["malscore"]))
        taxonomies.append(self.build_taxonomy(level, namespace, "Malfamily", result["malfamily"]))

        return taxonomies

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
            while not finished and tries <= 15: #wait max 15 mins
                time.sleep(60)
                response = requests.get(self.url + 'tasks/view/' + str(task_id))
                content = response.json()['task']['status']
                if content == 'reported':
                    finished = True
                tries += 1
            if not finished:
                self.error('CuckooSandbox analysis timed out')

            # Download the report
            response = requests.get(self.url + 'tasks/report/' + str(task_id) + '/json')
            resp_json = response.json()
            list_description = [x['description'] for x in resp_json['signatures']]
            if 'suricata' in resp_json.keys() and 'alerts' in resp_json['suricata'].keys():
                suri_alerts = [(x['signature'],x['dstip'],x['dstport'],x['severity']) for x in resp_json['suricata']['alerts']]
            else:
                suri_alerts = []
            hosts = [(x['ip'],x['hostname'],x['country_name']) for x in resp_json['network']['hosts']]
            uri = [(x['uri']) for x in resp_json['network']['http']]
            if self.service == 'url_analysis':
                self.report({
                    'signatures': list_description,
                    'suricata_alerts': suri_alerts,
                    'hosts': hosts,
                    'uri': uri,
                    'malscore': resp_json['malscore'],
                    'malfamily': resp_json['malfamily'],
                    'file_type': 'url',
                    'yara': resp_json['target']['url'] if 'target' in resp_json.keys() and 'url' in resp_json['target'].keys() else '-'
                })
            else:
                self.report({
                    'signatures': list_description,
                    'suricata_alerts': suri_alerts,
                    'hosts': hosts,
                    'uri': uri,
                    'malscore': resp_json['malscore'],
                    'malfamily': resp_json['malfamily'],
                    'file_type': "".join([x for x in resp_json['target']['file']['type']]),
                    'yara': [ x['name'] + " - " + x['meta']['description'] if 'description' in x['meta'].keys() else x['name'] for x in resp_json['target']['file']['yara'] ]
                })

        except requests.exceptions.RequestException as e:
            self.error(e)

        except Exception as e:
            self.unexpectedError(e)

if __name__ == '__main__':
    CuckooSandboxAnalyzer().run()

