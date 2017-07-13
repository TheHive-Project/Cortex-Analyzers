#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys
import json
import codecs
from cortexutils.analyzer import Analyzer
from abuse_finder import domain_abuse, ip_abuse, \
    email_abuse, url_abuse
import logging
logging.getLogger("tldextract").setLevel(logging.CRITICAL)


class AbuseFinderAnalyzer(Analyzer):

    def summary(self, raw):

        taxonomies = []
        if raw['abuse_finder'] and raw['abuse_finder'].get('abuse'):
            for abuse in raw['abuse_finder']['abuse']:
                taxonomies.append(self.build_taxonomy("info", "Abuse_Finder", "Address", abuse))
            return {"taxonomies": taxonomies}

    def abuse(self):
        if self.data_type == "ip":
            return ip_abuse(self.getData())
        elif self.data_type == "domain":
            return  domain_abuse(self.getData())
        elif self.data_type == "mail":
            return email_abuse(self.getData())
        elif self.data_type == "url":
            return url_abuse(self.getData())
        else:
            self.error("datatype not handled")

    def run(self):
        self.report({'abuse_finder':self.abuse()})

if __name__ == '__main__':
    AbuseFinderAnalyzer().run()
