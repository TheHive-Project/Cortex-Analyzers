#!/usr/bin/env python3
# encoding: utf-8

import requests
import time
import io
import zipfile
from os.path import basename
from triage import Client
from cortexutils.analyzer import Analyzer

class TriageAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.app_secret = self.get_param('config.api_key', None, 'Triage API key is missing')
        self.zip_pw = self.get_param('config.zip_pw')
        self.timeout = self.get_param('config.timeout')

        if self.timeout:
        # sleep some more, we all need to relax more
            self.timeout = int(self.timeout) + 60
        else:
            self.timeout = 200

        self.url = 'https://private.tria.ge/api'

    def summary(self, raw):
         taxonomies = []
         namespace = "Triage"

         value = "{}/10".format(raw['result']['sample'].get('score'))

         if raw['result']['sample'].get('score') == 0:
            verdict = "safe"
         elif raw['result']['sample'].get('score') < 5:
            verdict = "suspicious"
         else:
            verdict = "malicious"

         taxonomies.append(self.build_taxonomy(
         verdict,
         namespace,
         'Score',
         value
         ))

         return {"taxonomies": taxonomies}

    def file_submit(self, filename, filepath):

        token = self.app_secret
        connect = Client(token, root_url=self.url)

        # Check if it's a zip file and if it's password protected
        if zipfile.is_zipfile(filepath):
           zf = zipfile.ZipFile(filepath)
           for zinfo in zf.infolist():
               is_encrypted = zinfo.flag_bits & 0x1
               if is_encrypted:
                   password = self.zip_pw
                   sample = open(filepath, "rb")
                   submit = connect.submit_sample_file(filename, sample, password=password)
               else:
                   sample = open(filepath, "rb")
                   submit = connect.submit_sample_file(filename, sample)
        else:
           # Submit
           sample = open(filepath, "rb")
           submit = connect.submit_sample_file(filename, sample)

        # Wait
        time.sleep(self.timeout)
        # Enjoy
        retrive = connect.overview_report(submit['id'])
        return retrive

    def url_submit(self, data):

        # Submit
        token = self.app_secret
        connect = Client(token, root_url=self.url)
        submit = connect.submit_sample_url(data)
        # Wait
        time.sleep(self.timeout)
        # Enjoy
        retrive = connect.overview_report(submit['id'])
        return retrive

    def run(self):

            if self.data_type == 'ip' or self.data_type == 'url':
                data = self.get_param('data', None, 'Data is missing')

                if ':' in data:
                    result = self.url_submit(data)
                    self.report({'result': result})
                else:
                    self.error('Schema is missing')

            elif self.data_type == 'file':
                filepath = self.get_param('file', None, 'File is missing')
                filename = self.get_param('filename', basename(filepath))

                result = self.file_submit(filename, filepath)

                self.report({'result': result})
            else:
               data = self.get_param('data', None, 'Data is missing')

if __name__ == '__main__':
    TriageAnalyzer().run()
