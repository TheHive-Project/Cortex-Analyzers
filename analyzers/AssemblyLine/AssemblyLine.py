#!/usr/bin/env python3
# encoding: utf-8
import os
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
        al_client = get_client(self.assemblyline_host, apikey=(self.assemblyline_user,self.assemblyline_key), verify=False)
        filepath_filename = os.path.basename(filepath)
        response = al_client.submit(path=filepath, fname=filepath_filename)
        print(response)
        if response['sid'] != 0:
            for file in response['files']:
                print(file['sha256'])

    def search_for_analysis(self, hashValue):
        al_client = get_client(self.assemblyline_host, apikey=(self.assemblyline_user, self.assemblyline_key), verify=False)
        # file.md5	, file.sha1, file.sha256
        print(hashValue)
        response = al_client.search.submission("file.md5:")

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "AssemblyLine"
        predicate = "RetrieveAnalysis"
        value = "0"

        if self.service == "RetrieveAnalysis":
            predicate = "RetrieveAnalysis"

        result = {
            "success": True
        }

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def check_response(self, response):
        if type(response) is not dict:
            self.error('Bad response : ' + str(response))
        status = response.get('response_code', -1)
        if status != 200:
            self.error('Bad status : ' + str(status))
        results = response.get('results', {})
        return results

    def run(self):
        if self.service == 'AnalyseFile':
            filepath = self.get_param('file', None, 'File is missing')
            self.read_analysis_response(filepath=filepath)

        elif self.service == 'RetrieveAnalysis':
            hashValue = self.get_param('hash', None, 'Hash is missing')
            self.search_for_analysis(hashvalue=hashValue)

        else:
            self.error('Invalid service')


if __name__ == '__main__':
    AssemblyLineAnalyzer().run()
