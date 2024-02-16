#!/usr/bin/env python3
# encoding: utf-8


import subprocess
from cortexutils.analyzer import Analyzer


class WebsensePingAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.hostname = self.get_param('config.hostname', None)
        self.timeout = self.get_param('config.timeout', None)
        self.path = self.get_param('config.path', None)

def summary(self, raw):
    taxonomies = []
    if raw.get('Categories', None):
        value = raw['Categories']
        if value in self.get_param('config.malicious_categories', []):
            level = "malicious"
        elif value in self.get_param('config.suspicious_categories', []):
            level = "suspicious"
        elif value in self.get_param('config.safe_categories', []):
            level = "safe"
        else:
            level = "info"
        taxonomies.append(self.build_taxonomy(level, "Forcepoint", "WebsensePing", value))
    return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        if self.data_type in ("url", "ip", "domain","fqdn"):
            data = self.get_param('data', None, 'Data is missing')
            command = "export LD_LIBRARY_PATH={} && {}/WebsensePing -m 25 -url {} -s {} -t {}".format(self.path, self.path, data, self.hostname, self.timeout)
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = [line.decode('utf8') for line in process.stdout]
            report = {k.strip():v.strip() for k,v in [x.split("=") for x in output if x.find("=") != -1]}
            self.report(report)
        else:
            self.error('Invalid data type')


if __name__ == '__main__':
    WebsensePingAnalyzer().run()
