#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import requests
import hashlib
from requests.auth import HTTPBasicAuth
import time

class ProofPointForensicsAnalyzer(Analyzer):

	def __init__(self):
		Analyzer.__init__(self)
		self.service = self.get_param('config.service', None, 'ProofPoint service is missing')
		self.url = self.get_param('config.url', 'https://tap-api-v2.proofpoint.com', None)
		self.apikey = self.get_param('config.apikey', None, 'ProofPoint apikey is missing')
		self.secret = self.get_param('config.secret', None, 'ProofPoint secret is missing')
		self.verify = self.get_param('config.verifyssl', True, None)
		if not self.verify:
			from requests.packages.urllib3.exceptions import InsecureRequestWarning
			requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
		
	def summary(self, raw):
		
		taxonomies = []
		level = "info"
		namespace = "ProofPoint"
		predicate = "Category"
		value = "\"Unknown\""
		
		result = {
			'service': self.service,
			'dataType': self.data_type
		}
		if 'reports' in raw:
			for report in raw['reports']:
				threatstatus = report['threatStatus']
				if threatstatus == 'active':
					level = "malicious"
				if threatstatus == 'falsePositive':
					level = 'safe'
				if 'forensics' in report:
					if len(report['forensics']) > 0:
						for forensic in report['forensics']:
							if forensic['malicious']:
								if threatstatus == 'active':
									level = "malicious"
								if threatstatus == 'falsePositive':
									level = "suspicious"
								if 'note' in forensic:
									value = "\"{}\"".format(forensic['note'])
		taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
		return {"taxonomies": taxonomies}
		
	def run(self):
		Analyzer.run(self)
		
		try:
			user_agent = {'User-agent': 'Cortex Analyzer'}
			sha256 = None
			report = {}
			if self.service in ['query']:
				if self.data_type == 'file':
					filename = self.get_param('attachment.name', 'noname.ext')
					filepath = self.get_param('file', None, 'File is missing')
					sha256 = hashlib.sha256(open(filepath, 'r').read()).hexdigest()
				elif self.data_type == 'hash' and len(self.get_data()) == 64:
					sha256 = self.get_data()
				else:
					sha256 = hashlib.sha256(self.get_data()).hexdigest()
			else:
				self.error('unknown service')
			if sha256 != None:
				params = {'threatId': sha256}
				response = requests.get(self.url.strip('/') + '/v2/forensics', params=params, headers=user_agent, verify=self.verify, auth=HTTPBasicAuth(self.apikey, self.secret))
				if response.status_code == 200:
					data = response.json()
					report['known'] = True
					if 'reports' in data:
						report['reports'] = data['reports']
					if 'generated' in data:
						report['generated'] = data['generated']
					self.report(report)
				elif response.status_code == 400:
					self.error('bad request sent')
				elif response.status_code == 401:
					self.error('unauthorized access, verify your key and secret values')
				elif response.status_code == 404:
					report = {'known': False}
					self.report(report)
				else:
					self.error('unknown error')
			else:
				self.error('no hash defined')
		except requests.exceptions.RequestException as e:
			self.error(e)
		except Exception as e:
			self.unexpectedError(e)

if __name__ == '__main__':
	ProofPointForensicsAnalyzer().run()
