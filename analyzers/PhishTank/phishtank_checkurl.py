#!/usr/bin/env python
# encoding: utf-8
import sys
import os
import json
import codecs
import time
import re
import requests
from cortexutils.analyzer import Analyzer

class phishtankAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam(
            'config.service', None, 'Service parameter is missing')
        self.phishtank_key = self.getParam('config.key', None,
                                    'Missing PhishTank API key')

    def phishtank_checkurl(self, data):
    	#debug('>> phishtank_checkurl ' + str(data))
    	url = 'http://checkurl.phishtank.com/checkurl/'
    	postdata = {'url': data, 'format':'json','app_key': self.phishtank_key}
    	r = requests.post(url, data=postdata)
    	return json.loads(r.content)

    def summary(self,raw):
        if ('in_database' in raw) :
            return {'in_database':raw['in_database'],
            'verified':raw['verified'],
            'verified_at':raw['verified_at']}

    def run(self):
        if self.service == 'query':
        	if self.data_type == 'url':
        		data = self.getParam('data', None, 'Data is missing')
        		r = self.phishtank_checkurl(data)
        		if "success" in r['meta']['status']:
        			if r['results']['in_database']:
        				if "verified" in r['results']:
        					self.report({
        						'in_database': r['results']['in_database'],
        						'phish_detail_page': r['results']['phish_detail_page'],
        						'verified': r['results']['verified'],
        						'verified_at': r['results']['verified_at']
        					})
        				else:
        					self.report({
        							'in_database': r['results']['in_database'],
        							'phish_detail_page': r['results']['phish_detail_page']
        					})
        			else:
        				self.report({
        				 'in_database': 'False'
        				})
        		else:
        			self.report({
        					'errortext': r['errortext']
        			})
        	else:
        			self.error('Invalid data type')
        else:
        		self.error('Invalid service')

if __name__ == '__main__':
    phishtankAnalyzer().run()
    phishtankAnalyzer().summary()
