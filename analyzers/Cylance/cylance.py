#!/usr/bin/env python3
# encoding: utf-8

import requests
from cyapi.cyapi import CyAPI
from cortexutils.analyzer import Analyzer

class CylanceAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.tid = self.get_param('config.ten_id', None, 'Cylance Tenant ID is missing')
        self.app_id = self.get_param('config.app_id', None, 'Cylance App ID is missing')
        self.app_secret = self.get_param('config.app_secret', None, 'Cylance App secret is missing')
        self.region = self.get_param('config.region', None, 'Cylance region is missing')
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Cortex-Analyzer'
        }

    def summary(self, raw):
         taxonomies = []
         namespace = "Cylance"

         if raw['hashlookup'] == 'hash_not_found':
            taxonomies.append(self.build_taxonomy(
                'info',
                namespace,
                'Search',
                'No results'
            ))
         else:
            taxonomies.append(self.build_taxonomy(
                'malicious',
                namespace,
                'Score',
                raw['hashlookup']['sample'].get('cylance_score', 'Unknown')
            ))


         return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'hash':
            data = self.get_param('data', None, 'Data is missing')
            if len(data) != 64:
             self.error('Only SHA256 is supported')

            threats_results = {} 
            API = CyAPI(self.tid, self.app_id, self.app_secret, self.region)
            API.create_conn()
            threats = API.get_threat_devices(data)

            if threats.data:

                for x in range(len(threats.data)):
                    threats_results[x] = {'name': threats.data[x]['name'], 
                                         'state': threats.data[x]['state'], 
                                         'found': threats.data[x]['date_found'], 
                                         'status': threats.data[x]['file_status'], 
                                         'path': threats.data[x]['file_path'], 
                                          'ip': " , ".join(threats.data[x]['ip_addresses'])}

                if threats_results:
                    threat = API.get_threat(data)
                    threats_results['sample'] = {'sample_name': threat.data['name'], 
                                                'sha256': threat.data['sha256'], 
                                                'md5': threat.data['md5'], 
                                                'signed': threat.data['signed'], 
                                                'cylance_score': threat.data['cylance_score'], 
                                                'av_industry': threat.data['av_industry'], 
                                                'classification': threat.data['classification'], 
                                                'sub_classification': threat.data['sub_classification'], 
                                                'global_quarantined': threat.data['global_quarantined'], 
                                                'safelisted': threat.data['safelisted'], 
                                                'cert_publisher': threat.data['cert_publisher'], 
                                                'cert_issuer': threat.data['cert_issuer'], 
                                                'cert_timestamp': threat.data['cert_timestamp'], 
                                                'file_size': threat.data['file_size'], 
                                                'unique_to_cylance': threat.data['unique_to_cylance'], 
                                                'running': threat.data['running'], 
                                                'autorun': threat.data['auto_run'], 
                                                'detected_by': threat.data['detected_by'] }
            
                self.report({'hashlookup': threats_results})
            else:
                self.report({'hashlookup': 'hash_not_found'})
        else:
           self.error('Invalid data type')

if __name__ == '__main__':
    CylanceAnalyzer().run()
