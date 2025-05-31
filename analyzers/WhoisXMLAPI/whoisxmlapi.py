#!/usr/bin/env python
# -*- coding: utf-8 -*-

#######################################
#   Author: Unit777                   #
#######################################

import urllib2
import json
from cortexutils.analyzer import Analyzer
import logging

class WhoisXMLAPI(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.username = self.getParam(
            'config.username', None, 'Username parameter is missing')
        self.password = self.getParam(
            'config.password', None, 'Password parameter is missing')
        self.service = self.getParam(
            'config.service', None, 'Service parameter is missing')

    def run(self):
        if self.data_type == "domain" or self.data_type == "ip" or self.data_type == "url" or self.data_type == "fqdn":
            whoisxmlapiURL = 'https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=' + self.getData() + '&username=' + self.username + '&password=' + self.password + '&outputFormat=' + "JSON"
            #TODO: Add proxy capability
            result = json.loads(urllib2.urlopen(whoisxmlapiURL).read().decode('utf8'))
            if 'audit' in result:
                if 'createdDate' in result['audit']:
                    if '$' in result['audit']['createdDate']:
                        result['audit']['createdDate'] = js['audit']['createdDate']['$']
                if 'updatedDate' in result['audit']:
                    if '$' in result['audit']['updatedDate']:
                        result['audit']['updatedDate'] = js['audit']['updatedDate']['$']

            self.report({'whoisxmlapi': result})
                        

if __name__ == '__main__':
    WhoisXMLAPI().run()
