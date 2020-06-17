#!/usr/bin/env python
import json, requests, traceback

from cortexutils.analyzer import Analyzer


class SinkDBAnalyzer(Analyzer):
	def __init__(self):
		Analyzer.__init__(self)

		if self.data_type not in ['ip', 'domain', 'fqdn', 'mail']:
			self.error('SinkDB Analyzer only usable with the ip, domain, and mail data types.')

		self.apikey = self.get_param('config.key', None, 'HTTPS API Key needed for querying SinkDB.')
		self.data = self.get_data()

	def query_db(self, indicator):

		if self.data_type == 'ip':
			return self.parse_entries(json.loads(self.do_post("api_key={}&ipv4={}".format(self.apikey, self.data)).text))

		elif self.data_type in ('domain', 'fqdn'):
			return self.parse_entries(json.loads(self.do_post("api_key={}&domain={}".format(self.apikey, self.data)).text))

		elif self.data_type == 'mail':
			return self.parse_entries(json.loads(self.do_post("api_key={}&email={}".format(self.apikey, self.data)).text))

		else:
			raise TypeError('Error in query_db function. This error should not occur.')

	def parse_entries(self, entries):
		ret = {
				"Sinkhole": [],
				"Phishing": [],
				"Scanner": []
			}
		if entries['query_status'] == 'ok':
			for entry in entries['results']:
				if entry['source'] == 'sinkhole':
					ret['Sinkhole'].append(entry)
				elif entry['source'] == 'awareness':
					ret['Phishing'].append(entry)
				elif entry['source'] == 'scanner':
					ret['Scanner'].append(entry)
			return ret
		elif entries['query_status'] == 'no_results':
			return ret
		elif entries['query_status'] == 'invalid_ipaddress':
			self.error("SinkDB did not recognize the IP as valid. Here is the full response:\n{}".format(json.dumps(entries)))					
		else:
			self.error("There was an unknown error communicating with the SinkDB API. Here is the full response:\n{}".format(json.dumps(entries)))

	def do_post(self, data):
		return requests.post('https://sinkdb-api.abuse.ch/api/v1/', headers={"Content-Type": "application/x-www-form-urlencoded"}, data=data)

	def run(self):
		try:
			self.report(self.query_db(self.data))
		except:
			self.error("Error when attempting to retrieve data:\n{}".format(traceback.format_exc()))

	def summary(self, raw):
		taxonomies = []

		for k, v in raw.iteritems():
			if v:
				taxonomies.append(self.build_taxonomy('suspicious', 'SinkDB', k, 'True'))
			else:
				taxonomies.append(self.build_taxonomy('safe', 'SinkDB', k, 'False'))

		return {
			"taxonomies": taxonomies
		}


if __name__ == '__main__':
	SinkDBAnalyzer().run()
