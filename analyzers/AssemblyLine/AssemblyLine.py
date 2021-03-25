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

    def run(self):
        if self.data_type == 'file':
            try:
                self.filepath = self.getParam('file', None, 'File is missing')
                self.filename = self.getParam('attachment.name', 'noname.ext')
                parsingResult = self.AnalyseFile()
                self.report(parsingResult)
            except Exception as e:
                self.unexpectedError(e)

        elif self.data_type == 'url':
            try:
                self.url = self.get_data()
                parsingResult = self.AnalyseURL()
                self.report(parsingResult)
            except Exception as e:
                self.unexpectedError(e)

        elif self.data_type == 'hash':
            try:
                self.hash = self.get_data()
                parsingResult = self.RetrieveAnalysis()
                self.report(parsingResult)
            except Exception as e:
                self.unexpectedError(e)

        else:
            self.notSupported()

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Assemblyline"

        if self.service == "AnalyseFile":
            predicate = "AnalyseFile"
        elif self.service == "AnalyseURL":
            predicate = "AnalyseURL"
        elif self.service == "RetrieveAnalysis":
            predicate = "RetrieveAnalysis"

        value = ''
        print(raw)

    def AnalyseFile(self):
        al_client = get_client(self.assemblyline_host, apikey=(self.assemblyline_user, self.assemblyline_key), verify=False)
        response = al_client.submit(path=self.filepath, fname=self.filename)
        return response

    def AnalyseURL(self):
        al_client = get_client(self.assemblyline_host, apikey=(self.assemblyline_user, self.assemblyline_key), verify=False)
        response = al_client.submit(url=self.url)
        return response

    def RetrieveAnalysis(self):
        al_client = get_client(self.assemblyline_host, apikey=(self.assemblyline_user, self.assemblyline_key), verify=False)
        submissions = al_client.search.submission("files.sha256:" + self.hash)
        return json.dumps(submissions)

if __name__ == '__main__':
    AssemblyLineAnalyzer().run()
