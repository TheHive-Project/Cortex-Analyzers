#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
import requests
import re


class InoitsuAnalyzer(Analyzer):
	def __init__(self):
		Analyzer.__init__(self)

	def verify_email_format(self, email):
		email_regex = '^(?i)[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
		if(re.search(email_regex,email)):
			return True
		else:
			return False

	def remove_html_tags(self, html):
		regex = re.compile('<.*?>')
		cleantext = re.sub(regex, '', html)
		return cleantext

	def inoitsu_check(self,email):
		url ="https://www.hotsheet.com/inoitsu/"
		data = {'act' : email, 'accounthide' : 'test', 'submit' : 'Submit'}
		r = requests.post(url, data=data, timeout=10)
		response = r.text
		if 'BREACH DETECTED!' in response:
			cleantext = self.remove_html_tags(response)
			text = cleantext.replace('&nbsp;','')
			Breached_data_finder = re.search('Breached Personal Data(.*)Critical Identity Alerts', text)
			Breached_data = Breached_data_finder.group(1)[1:]
			Critical_data_finder = re.search('Critical Identity Alerts(.*)Total Breaches', text)
			Critical_data = Critical_data_finder.group(1)[1:]
			Total_breaches_finder = re.search('Total Breaches(.*)Most Recent Breach', text)
			Total_breaches = Total_breaches_finder.group(1)[1:]
			Most_recent_breach_finder = re.search('Most Recent Breach(.*)Relative Exposure Rating', text)
			Most_recent_breach = Most_recent_breach_finder.group(1)[2:]
			Exposure_rating_finder = re.search('Relative Exposure Rating(.*)breach data from', text)
			Exposure_rating = Exposure_rating_finder.group(1)[2:]
			result = dict(Email = email, Leaked = True, Breached_data = Breached_data, Critical_data = Critical_data,
			Total_breaches = int(Total_breaches), Most_recent_breach = Most_recent_breach,
			Exposure_rating = Exposure_rating)
			return result
		else:
			return dict(Email = email, Leaked = False)

	def summary(self, raw):
		taxonomies = []
		level = "info"
		namespace = "Inoitsu"
		predicate = "Compromised"
		leaked = raw.get("Leaked")
		if leaked:
			level = "malicious"
			value = "True"
		else:
			level = "safe"
			value = "False"
		taxonomies.append(
		self.build_taxonomy(level, namespace, predicate, value)
		)
		return {"taxonomies": taxonomies}

	def run(self):
		email = self.get_data()
		if not email:
			self.error('No email given.')
		try:
			if self.verify_email_format(email):
				result = self.inoitsu_check(email)
				self.report(result)
			else:
				self.error('Your input is not an email.')
		except Exception as e:
			self.error(str(e))

if __name__ == "__main__":
	InoitsuAnalyzer().run()
