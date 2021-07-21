#!/usr/bin/env python3
# -*- coding: utf-8 -*

from tenable.sc import TenableSC
from cortexutils.analyzer import Analyzer

class ScanResultTenableAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.host = self.get_param(
            'config.host', None, 'Missing Nessus scanner host')
        self.port = self.get_param(
            'config.port', None, 'Missing Nessus scanner port')
        self.access_key = self.get_param(
            'config.access_key', None, 'Missing Nessus scanner access_key')
        self.secret_key = self.get_param(
            'config.secret_key', None, 'Missing Nessus scanner secret_key')
        self.password = self.get_param(
            'config.password')
        self.username = self.get_param(
            'config.username')
    
    def summary(self, raw):

        taxonomies = []
        level = "info"
        namespace = "Tenable"
        predicate = "Info"

        if raw["tenable"]["Info"] >= 0:
            value = raw["tenable"]["Info"]
            taxonomies.append(self.build_taxonomy(level, namespace, "Info", value))
        if raw["tenable"]["Low"]>= 0:
            value = raw["tenable"]["Low"]
            taxonomies.append(self.build_taxonomy(level, namespace, "Low", value))
        if raw["tenable"]["Medium"] >= 0:
            value = raw["tenable"]["Medium"]
            level = "suspicious"
            taxonomies.append(self.build_taxonomy(level, namespace, "Medium", value))
        if raw["tenable"]["High"] >= 0:
            value = raw["tenable"]["High"]
            level = "suspicious"
            taxonomies.append(self.build_taxonomy(level, namespace, "High", value))
        if raw["tenable"]["Critical"] >= 0:
            value = raw["tenable"]["Critical"]
            level = "malicious"
            taxonomies.append(self.build_taxonomy(level, namespace, "Critical", value))

        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        data = self.get_param('data', None, 'Data is missing')

        if self.data_type != 'hostname' and self.data_type != 'ip':
            self.error('Invalid data type')

        sc = TenableSC(
                host=self.host,
                port=self.port,
                access_key=self.access_key,
                secret_key=self.secret_key)
        Medium = 0
        Critical = 0
        Low = 0
        Info = 0
        High = 0
        i = 0
        if sc is not None:
            if self.data_type == 'ip':
                results = sc.analysis.vulns((self.data_type, '=', data))
                if results is not None:

                    if results is not None:
                        for i, vuln in enumerate(results):
                            i += 1
                            if vuln['riskFactor'] == 'Medium':
                                Medium += 1
                            elif vuln['riskFactor'] == 'Critical':
                                Critical += 1
                            elif vuln['riskFactor'] == 'High':
                                High += 1
                            elif vuln['riskFactor'] == 'Low':
                                Low += 1
                            else:
                                Info += 1

                        self.report({
                                "tenable": {
                                    "total": i,
                                    "Medium": Medium,
                                    "Critical": Critical,
                                    "Low": Low,
                                    "Info": Info,
                                    "High": High
                                }
                            })
                
                else:
                   self.error(f'Not results were found for {data}') 
        else:
            self.error('Unable to connect to Tenable')


if __name__ == '__main__':
    ScanResultTenableAnalyzer().run()
