#!/usr/bin/python3
#coding:utf-8

from cortexutils.analyzer import Analyzer
from requests import post
from json import dumps, loads
from base64 import b64encode

class GoogleAPI_Vision(Analyzer):

	def __init__(self):
		Analyzer.__init__(self)
		self.api_endpoint = "https://vision.googleapis.com/v1/images:annotate"

	def make_api_call(self, url: str, query: str, api_key: str, https_proxy: str, maxResults: int, datatype: str, file=None) -> dict:

		header = {
			"Content-Type" : "application/json"
		}

		data = {
		 	"requests": [{
		     	"image": {
		        	"source": {
		          		"imageUri": query
		        	}
		      	},
		      	"features": [{
		          "type": "WEB_DETECTION",
		          "maxResults": maxResults
		        }]
		    }]
		}

		if datatype == "file":
			try:
				query = b64encode(open(file, "rb").read()).decode("utf-8")
			except FileNotFoundError:
				self.error("Error while reading provided file")
			else:
				del data["requests"][0]["image"]["source"]
				data["requests"][0]["image"]["content"] = query

		try:
			api_answser = loads(post(url + "?key=" + api_key, data=dumps(data), headers=header, proxies=https_proxy).text)
		except ValueError:
			self.error("Cannot parse JSON answer from server")
		else:
			return api_answser

	def get_artifacts(self, google_results: str) -> list:
		return [ item["url"] for item in google_results['responses'][0]["webDetection"]["pagesWithMatchingImages"]]

	def run(self):
		query = self.getData()

		if query is None:
			self.error("You must provide a file or a valid url to this image")

		api_key = self.getParam("config.api_key")
		if api_key is None:
			self.error("You need an API key for Google Vision API")

		https_proxy = { "https" : self.getParam("config.proxy_https") }
		maxResults = self.getParam("config.max_Result")
		maxResults = maxResults if maxResults is not None else 100

		answer = self.make_api_call(self.api_endpoint, query, api_key, https_proxy, maxResults, self.data_type, file=self.getParam("file"))
		self.report({ 'api_full_report' : answer })

	def summary(self, raw):
		
		number_of_image_found = self.build_taxonomy("info", "GoogleVisionAPI", "pagesWithMatchingImages", str(len(raw["api_full_report"]["responses"][0]["webDetection"]["pagesWithMatchingImages"])))
		number_of_look_alike = self.build_taxonomy("info", "GoogleVisionAPI", "visuallySimilarImages", str(len(raw["api_full_report"]["responses"][0]["webDetection"]["visuallySimilarImages"])))

		return { "taxonomies" : [number_of_look_alike, number_of_image_found] }


if __name__ == "__main__":
	GoogleAPI_Vision().run()
