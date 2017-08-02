#!/usr/bin/python
#encoding: utf-8
from cortexutils.analyzer import Analyzer
import json, re, sys, requests

class BluecoatAnalyzer(Analyzer):

		def __init__(self):
			Analyzer.__init__(self)
			self.BC_url = "https://sitereview.bluecoat.com/"
			self.BC_parameter_name = "url"
			self.BC_sitereview = "sitereview.jsp"
			self.BC_rest_page = "rest/categorization"

		"""
			Extract desired field through a regex
			- category
			- id
			- date
		"""
		def parse_answer(self, categorization, ratedate):

			REGEX_NUM = r"catdesc\.jsp\?catnum=(\d+)"
			REGEX_CATE = r">([\w\s\/]+)<\/a>"
			REGEX_DATE = r"Last Time Rated\/Reviewed:(.*)<img"

			if categorization != "":
				result = {}
				try:
					result["category"] = re.findall(REGEX_CATE, categorization)[0]
					result["id"] = re.findall(REGEX_NUM, categorization)[0]
					result["date"] = re.findall(REGEX_DATE, ratedate)
					if result["date"] == []: result["date"] = False
					else : result["date"] = result["date"][0]

				except Exception as e:
					result = None

				return result


		"""
			return JSON formated data provided by Bluecoat REST API
		"""
		def callBlueCoatAPI(self, host):
			session = requests.session()
			try:
				# First connexion in order to get a SESSION ID, used for the second request
				session.get(self.BC_url + self.BC_sitereview)
				BC_json_answer = session.post(self.BC_url + self.BC_rest_page, data={self.BC_parameter_name : host})
				return json.loads(BC_json_answer.text)
			except Exception as e:
				self.error(str(e))


		"""
			retrieve domain from url
		"""
		def url_to_domain(self, url):
			REGEX_DOMAIN = r"(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n]+)\/?"
			try:
				return  re.findall(REGEX_DOMAIN, url)[0]
			except:
				return None


		def summary(self, raw):
			taxonomies = []
			level = "info"
			namespace = "BC"
			predicate = "Categorization"
			value = "\""+raw["category"]+"\""

			if value == "\"Uncategorized\"": level = "suspicious"

			taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
			return {"taxonomies" : taxonomies}

		"""
			retrieve domain from url
		"""
		def url_to_domain(self, url):
			REGEX_DOMAIN = r"(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n]+)\/?"
			try:
				return  re.findall(REGEX_DOMAIN, url)[0]
			except:
				return None


		def run(self):

			if self.data_type == "domain" or self.data_type == "url":

				if self.data_type == "url":
					domain = self.url_to_domain(self.getData())
					if domain != None: JSON_answer = self.callBlueCoatAPI(domain)
					else: self.error("Domain not found")

				else: JSON_answer = self.callBlueCoatAPI(self.getData())

				if JSON_answer != None:
					try:
						result = self.parse_answer(JSON_answer["categorization"], JSON_answer["ratedate"])
						result["hote"] = str(self.getData())
						return self.report(result)
					except Exception as e:
						try:
							return self.error("%s : %s" % (JSON_answer["errorType"], JSON_answer["error"]))
						except Exception as b:
							return self.error(str(b))

			elif self.data_type == "url":
				self.url_to_domain(self.getData())

			else:
				return self.error("Invalid data type !")


if __name__ == '__main__':
    BluecoatAnalyzer().run()
