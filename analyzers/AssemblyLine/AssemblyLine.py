#!/usr/bin/env python3
# encoding: utf-8

import sys
import json

from assemblyline_client import get_client
from cortexutils.analyzer import Analyzer


class AssemblyLineAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')

        self.assemblyline_host = self.get_param('config.al_host', None, 'Missing Assemblyline Host')
        self.assemblyline_user = self.get_param('config.al_user', None, 'Missing Assemblyline User')
        self.assemblyline_key = self.get_param('config.al_key', None, 'Missing Assemblyline Key')

        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.proxies = self.get_param('config.proxy', None)

    def read_analysis_response(self, filepath):
        al_client = get_client(self.assemblyline_host, auth=(self.assemblyline_user,self.assemblyline_key), verify=False)
        analyse_file = al_client.submit(filepath)
        response = json.loads(analyse_file)
        if response.sid != 0:
            print('SID Detected')
            for file in response['files']:
                print(file.sha256)

    def run(self):
        if self.service == 'AnalyseFile':
            filename = self.get_param('filename', 'none.ext')
            filepath = self.get_param('file', None, 'File is missing')
            self.read_analysis_response(filepath=filepath)

        elif self.service == 'RetrieveAnalysis':
            if self.data_type == 'file':
                var = 'not yet implemented'
            elif self.data_type == 'hash':
                var = 'not yet implemented'
            else:
                self.error('Invalid data type')
        else:
            self.error('Invalid service')


if __name__ == '__main__':
    AssemblyLineAnalyzer().run()
