#!/usr/bin/env python3
# encoding: utf-8

import requests
from cortexutils.analyzer import Analyzer

class CIRCLHashlookupAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.url = 'https://hashlookup.circl.lu'

    def summary(self, raw):
         taxonomies = []
         namespace = "CIRCLHashlookup"

         if raw.get('CRC32'):
            verdict = "safe"
            result = "known"
         else:
            verdict = "info"
            result = "unkown"

         taxonomies.append(self.build_taxonomy(
         verdict,
         namespace,
         'Result',
         result,
         ))

         return {"taxonomies": taxonomies}

    def run(self):
            if self.data_type == 'hash':
                data = self.get_param('data', None, 'Data is missing')

                headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
                session = requests.Session()
                if len(data) == 32:
                    s = session.get(self.url + '/lookup/md5/' + data, headers=headers)
                elif len(data) == 40:
                    s = session.get(self.url + '/lookup/sha1/' + data, headers=headers)
                else:
                    self.error('Unsupported hash type')

                s.close()
                response = s.json()
                try:
                   self.report(response)
                except Exception as e:
                   self.error('Invalid data type')
            else:
                self.error('Invalid data type')

if __name__ == '__main__':
    CIRCLHashlookupAnalyzer().run()