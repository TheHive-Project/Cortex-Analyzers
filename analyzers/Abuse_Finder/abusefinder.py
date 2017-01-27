#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys
import json
import codecs
from cortexutils.analyzer import Analyzer
from abuse_finder import domain_abuse, ip_abuse, \
    email_abuse, url_abuse

class AbuseFinderAnalyzer(Analyzer):

    def abuse(self):
        if self.data_type == "ip":
            return json.dumps(ip_abuse(self.getData()))
        elif self.data_type == "domain":
            return json.dumps(domain_abuse(self.getData()))
        elif self.data_type == "mail":
            return json.dumps(email_abuse(self.getData()))
        elif self.data_type == "url":
            return json.dumps(url_abuse(self.getData()))
        else:
            self.error("datatype not handled")

    def run(self):
        print self.abuse()

if __name__ == '__main__':
    AbuseFinderAnalyzer().run()
