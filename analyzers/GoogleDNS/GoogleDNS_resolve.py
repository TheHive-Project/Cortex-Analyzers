#!/usr/bin/env python3
#encoding: utf-8

from requests import get
from cortexutils.analyzer import Analyzer
from DNS_records import RECORDS, CODE
from json import loads
from traceback import format_exc

class GoogleDNS_resolve(Analyzer):

	def __init__(self):
		Analyzer.__init__(self)
		self.url = "https://dns.google.com/resolve?"
		self.proxies = None
		self.answer = None

	def resolve(self, query):

		query = {
			"name" : query,
			"type" : "ANY"
		}

		try:
			data = loads(get(self.url, params=query, proxies=self.proxies).text)
		except Exception as e:
			self.report(format_exc())
		else:

			if data['Status'] == 0: # DNS response code
				if 'Answer' in data: # Maybe nothing is found

					for records in data['Answer']: # for each records found by Google
						try:
							records["type"] = RECORDS[records["type"]]  # replace IANA code by record name
						except KeyError:
							data["Error"] = "Invalid IANA code : {0}".format(int(records["type"]))	# Maybe using a special code
				else:
					data['Answer'] = [] 
				
			else: # If the DNS response match an error code
				try:
					# known DNS error code
					data["Error"] = "Error for {0} : {1}".format(data['Question'][0]['name'], CODE[int(data["Status"])])
				except KeyError:
					# DNS error code is unknow
					data["Error"] = "Unknow error : {0}".format(int(data["Status"]))
				
			self.answer = data
			self.answer['Question'][0]['type'] = RECORDS[data['Question'][0]['type']] # eplace IANA code by record name 
			self.answer["Status"] = CODE[int(data["Status"])] # replace DNS response code by name
				
	def run(self):
		if self.data_type not in ["ip", "domain", "fqdn"]:
			self.error("Wrong data type")

		target = self.getData()

		self.proxies = {
			"https" : self.getParam("config.proxy_https"),
			"http" : self.getParam("config.proxy_http")
		}

		target = ".".join(target.split('.')[::-1]) + '.in-addr.arpa' if self.data_type == "ip" else target

		self.resolve(target)
		if self.answer != None:
			self.report(self.answer)
		else:
			self.error("Something went wrong")

	def summary(self, raw):
		count = self.build_taxonomy("info", "GoogleDNS", "RecordsCount", len(self.answer["Answer"]))
		return { "taxonomies" : [count]}

if __name__ == "__main__":
	GoogleDNS_resolve().run()
