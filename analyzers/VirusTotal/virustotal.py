#!/usr/bin/env python
# encoding: utf-8
import sys
import os
import json
import codecs
import time
import hashlib

from virustotal_api import PublicApi as VirusTotalPublicApi
from cortexutils.analyzer import Analyzer


class VirusTotalAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam('config.service', None, 'Service parameter is missing')
        self.virustotal_key = self.getParam('config.key', None, 'Missing VirusTotal API key')
        self.polling_interval = self.getParam('config.polling_interval', 60)

    def wait_file_report(self, id):
        results = self.check_response(self.vt.get_file_report(id))
        code = results.get('response_code', None)
        if code == 1:
            self.report(results)
        else:
            time.sleep(self.polling_interval)
            self.wait_file_report(id)

    def wait_url_report(self, id):
        results = self.check_response(self.vt.get_url_report(id))
        code = results.get('response_code', None)
        if code == 1:
            self.report(results)
        else:
            time.sleep(self.polling_interval)
            self.wait_url_report(id)

    def check_response(self, response):
        if type(response) is not dict:
            self.error('Bad response : ' + str(response))
        status = response.get('response_code', -1)
        if status == 204:
            self.error('VirusTotal api rate limit exceeded (Status 204).')
        if status != 200:
            self.error('Bad status : ' + str(status))
        results = response.get('results', {})
        if 'verbose_msg' in results:
            print >> sys.stderr, str(results.get('verbose_msg'))
        return results

        # 0 => not found
        # -2 => in queue
        # 1 => ready

    def read_scan_response(self, response, func):
        results = self.check_response(response)
        code = results.get('response_code', None)
        scan_id = results.get('scan_id', None)
        if code == 1 and scan_id is not None:
            func(scan_id)
        else:
            self.error('Scan not found')

    def summary(self, raw):

        taxonomy = {"level": "clean", "namespace": "VT", "predicate": "Score", "value": 0}
        taxonomies = []

        result = {
            "has_result": True
        }

        if(raw["response_code"] != 1):
            result["has_result"] = False

        result["positives"] = raw.get("positives", 0)
        result["total"] = raw.get("total", 0)

        if("scan_date" in raw):
            result["scan_date"] = raw["scan_date"]

        if self.service == "get":
            if("scans" in raw):
                result["scans"] = len(raw["scans"])

            if("resolutions" in raw):
                result["resolutions"] = len(raw["resolutions"])

            if("detected_urls" in raw):
                result["detected_urls"] = len(raw["detected_urls"])

            if("detected_downloaded_samples" in raw):
                result["detected_downloaded_samples"] = len(
                    raw["detected_downloaded_samples"])

        taxonomy['value'] = "{}/{}".format(result["positives"], result["total"])
        if result["positives"] == 0:
            taxonomy["level"] = "safe"
        elif result["positives"] < 5 :
            taxonomy["level"] = "suspicious"
        else:
            taxonomy["level"] = "malicious"

        taxonomies.append(taxonomy)
        result = {"taxonomies": taxonomies}
        return result

    def run(self):
        Analyzer.run(self)

        self.vt = VirusTotalPublicApi(self.virustotal_key)

        if self.service == 'scan':
            if self.data_type == 'file':
                filename = self.getParam('attachment.name', 'noname.ext')
                filepath = self.getParam('file', None, 'File is missing')
                self.read_scan_response(self.vt.scan_file(
                    (filename, open(filepath, 'rb'))), self.wait_file_report)
            elif self.data_type == 'url':
                data = self.getParam('data', None, 'Data is missing')
                self.read_scan_response(
                    self.vt.scan_url(data), self.wait_url_report)
            else:
                self.error('Invalid data type')
        elif self.service == 'get':
            if self.data_type == 'domain':
                data = self.getParam('data', None, 'Data is missing')
                self.report(self.check_response(
                    self.vt.get_domain_report(data)))
            elif self.data_type == 'ip':
                data = self.getParam('data', None, 'Data is missing')
                self.report(self.check_response(self.vt.get_ip_report(data)))
            elif self.data_type == 'file':

                hashes = self.getParam('attachment.hashes',
                                    None)
                if hashes is None:
                    filepath = self.getParam('file', None, 'File is missing')
                    hash = hashlib.sha256(open(filepath, 'r').read()).hexdigest();
                else:
                # find SHA256 hash
                    hash = next(h for h in hashes if len(h) == 64)

                self.report(self.check_response(self.vt.get_file_report(hash)))

            elif self.data_type == 'hash':
                data = self.getParam('data', None, 'Data is missing')
                self.report(self.check_response(self.vt.get_file_report(data)))
            else:
                self.error('Invalid data type')
        else:
            self.error('Invalid service')


if __name__ == '__main__':
    VirusTotalAnalyzer().run()
