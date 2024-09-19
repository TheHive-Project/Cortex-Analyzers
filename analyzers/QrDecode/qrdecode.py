#!/usr/bin/env python3
# Author : THA-CERT

import sys
import os
import re
from cortexutils.analyzer import Analyzer
from pyzbar.pyzbar import decode, ZBarSymbol
from PIL import Image
from pdf2image import convert_from_path

class QrDecode(Analyzer):
	def __init__(self):
		Analyzer.__init__(self)
		self.filename = self.get_param("filename", None, "Filename is missing.")
		self.num_page = None
		self.nb_page = None
		self.file_format = None
		self.message = ""
		self.total_qr_codes = 0
		self.nb_qrcode = 0
		self.num_qrcode = 0
		self.results_list = []
		self.regex_ipv4 = r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
		self.regex_domain = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,6}(\.[A-Za-z]{2,6})?$'
		# Errors Dictionary
		self.errors = ("Unable to read QR code / No QR code detected", "File format not supported", "PDF conversion failed")
		self.err = None

	def run(self):
		self.check_format()
		self.stats()
		self.report({"results_list": self.results_list, "stats": self.stats})

	def summary(self, raw):
		taxonomies = []
		level = "info"
		namespace = "QrDecode"
		predicate_totalqr = "Total_QR"

		if "stats" in raw:
			stats = raw["stats"]
			if "total_qr_codes" in stats:
				total_qr_codes = stats["total_qr_codes"]
				taxonomies.append(self.build_taxonomy(level, namespace, predicate_totalqr, total_qr_codes))

		return {"taxonomies": taxonomies}

	def artifacts(self, raw):
		artifacts = []

		if raw['results_list']:
			for result in raw['results_list']:
				tags = ["from:" + str(self.filename)]
				if 'results' in result and 'data_type' in result['results'] and 'data' in result['results']:
					data_type = result['results']['data_type']
					data = result['results']['data']
					message = result['results']['info']

					if data_type != "other":
						tags.append("autoImport:true")

					if data_type == "mail":
						match = re.search(r'MATMSG:TO:([^;]+);', data)
						if match:
							data = match.group(1)

					if data_type == "btc_address":
						match = re.match(r'bitcoin:((bc1[0-9a-zA-Z]{25,39})|([13][a-km-zA-HJ-NP-Z1-9]{25,34}))', data)
						if match:
							data = match.group(1)

					artifacts.append(self.build_artifact(data_type, data, tags=tags, message=message))
		return artifacts

	def operations(self, raw):
		operations = []
		types = ""
		# Tags for filtered results
		if raw['results_list']:
			for result in raw['results_list']:
				if 'results' in result and 'data_type' in result['results'] and 'data' in result['results']:
					data_type = result['results']['data_type']
					data_category = result['results']['data_category']
					if data_type != 'Unknown' and data_type not in types:
						types += str(data_type) + ","

			operations.append(self.build_operation('AddTagToArtifact', tag="Data_Type:" + types[:-1]))

		return operations

	def check_format(self):
		self.file = self.get_param('file')
		# 8 first hex of file
		with open(self.file, 'rb') as fd:
			file_head = fd.read(8)
			integer_lst = [i for i in file_head]
			hex_lst = [hex(i) for i in integer_lst]

		# Tuples of hex files :
		jpg_jpeg = ("0xff", "0xd8", "0xff")
		png = ("0x89", "0x50", "0x4e", "0x47", "0xd", "0xa", "0x1a", "0xa")
		gif = ("0x47", "0x49", "0x46", "0x38")
		pdf = ("0x25", "0x50", "0x44", "0x46", "0x2d")

		if all(hex_lst[i].startswith(jpg_jpeg) for i in range(3)):
			self.file_format = "JPG"
			self.qr_decode(self.file)
			if self.nb_qrcode == 0:
				self.err = self.errors[0]
		elif all(hex_lst[i].startswith(png) for i in range(8)):
			self.file_format = "PNG"
			self.qr_decode(self.file)
			if self.nb_qrcode == 0:
				self.err = self.errors[0]
		elif all(hex_lst[i].startswith(gif) for i in range(4)):
			self.file_format = "GIF"
			self.qr_decode(self.file)
			if self.nb_qrcode == 0:
				self.err = self.errors[0]
		elif all(hex_lst[i].startswith(pdf) for i in range(5)):
			self.file_format = "PDF"
			self.pdf_converter()
		else:
			self.file_format = "UNKNOWN"
			self.err = self.errors[1]

	def pdf_converter(self):
		try:
			images = convert_from_path(self.file)
			os.mkdir(self.file +'_converted')
			os.chdir(self.file +'_converted')
		except:
			self.err = self.errors[2]

		for i in range(len(images)):
			page_file = 'page' + str(i) + '.jpg'
			# Save pdf pages as images
			images[i].save(page_file, 'JPEG')
			self.nb_page = len(images)
			self.nb_qrcode = 0
			self.num_page = i + 1
			try:
				self.qr_decode(page_file)
				if self.nb_qrcode == 0:
					pass
			except:
				raise

	def qr_decode(self, file):
		decodeqr = decode(Image.open(file), symbols=[ZBarSymbol.QRCODE])

		# Data Type
		data_types = ("URL", "WIFI_Credentials", "FTP_server", "SFTP_server", "Emailing",
		"SMS", "EPC", "Bitcoin", "Bitcoin_Cash", "Ethereum","Litecoin", "Dash",
		"Phone_Number", "vCard", "MeCard", "Geo_Location", "Calendar_Event", "FQDN", "IP_Address", "Domain")

		data_categories = ("Web_and_Network_Data", "Communication_Data", "Financial_and_Transactional_Data")

		data_type_list = ("btc_address", "domain", "fqdn", "ip", "mail","other", "url")

		self.nb_qrcode = (len(decodeqr))
		self.total_qr_codes += self.nb_qrcode
		string = ""

		for i in range(self.nb_qrcode):
			self.num_qrcode += 1
			string = decodeqr[i].data.decode('utf8')

			# Determining the data type
			if string.startswith("http"):
				data_category = data_categories[0]
				data_type = data_type_list[6]
				self.message = data_types[0]
			elif string.startswith("www"):
				data_category = data_categories[0]
				data_type = data_type_list[2]
				self.message = data_types[17]
			elif string.startswith("ftp://"):
				data_category = data_categories[0]
				data_type = data_type_list[6]
				self.message = data_types[2]
			elif string.startswith("sftp://"):
				data_category = data_categories[0]
				data_type = data_type_list[6]
				self.message = data_types[3]
			elif re.fullmatch(self.regex_domain, string):
				data_category = data_categories[0]
				data_type = data_type_list[1]
				self.message = data_types[19]
			elif re.fullmatch(self.regex_ipv4, string):
				data_category = data_categories[0]
				data_type = data_type_list[3]
				self.message = data_types[18]
			elif "WIFI:" in string:
				data_category = data_categories[0]
				data_type = data_type_list[5]
				self.message = data_types[1]
			elif "mailto:" in string or "MATMSG:" in string or "SMTP:" in string:
				data_category = data_categories[1]
				data_type = data_type_list[4]
				self.message = data_types[4]
			elif "smsto:" in string or "sms:" in string:
				data_category = data_categories[1]
				data_type = data_type_list[5]
				self.message = data_types[5]
			elif "BCD" in string:
				data_category = data_categories[2]
				data_type = data_type_list[5]
				self.message = data_types[6]
			elif "bitcoin:" in string:
				data_category = data_categories[2]
				data_type = data_type_list[0]
				self.message = data_types[7]
			elif "bitcoincash:" in string:
				data_category = data_categories[2]
				data_type = data_type_list[5]
				self.message = data_types[8]
			elif "ethereum:" in string:
				data_category = data_categories[2]
				data_type = data_type_list[5]
				self.message = data_types[9]
			elif "litecoin:" in string:
				data_category = data_categories[2]
				data_type = data_type_list[5]
				self.message = data_types[10]
			elif "dash:" in string:
				data_category = data_categories[2]
				data_type = data_type_list[5]
				self.message = data_types[11]
			elif "tel:" in string:
				data_category = data_categories[1]
				data_type = data_type_list[5]
				self.message = data_types[12]
			elif "VCARD" in string:
				data_category = data_categories[1]
				data_type = data_type_list[5]
				self.message = data_types[13]
			elif "MECARD:" in string:
				data_category = data_categories[1]
				data_type = data_type_list[5]
				self.message = data_types[14]
			elif "geo:" in string.lower():
				data_category = data_categories[1]
				data_type = data_type_list[5]
				self.message = data_types[15]
			elif "VEVENT" in string:
				data_category = data_categories[1]
				data_type = data_type_list[5]
				self.message = data_types[16]

			else:
				data_category = "Unknown"
				data_type = data_type_list[5]
				self.message = None

			# OUTPUT JSON
			results = {
				"QR": self.num_qrcode,
				"data_category": data_category,
				"data_type": data_type,
				"info": self.message,
				"data": string,
				"brute_data": str(decodeqr[i])
			}

			if self.num_page is not None:
				results["page"] = self.num_page

			self.results_list.append({"results": results})

	def stats(self):
		self.stats = {
			"file_name": self.filename,
			"file_extension": self.file_format,
			"total_qr_codes": self.total_qr_codes
		}

		if self.nb_page is not None:
			self.stats["total_pages_pdf"] = self.nb_page
			
		if self.err is not None:
			self.stats["error"] = self.err

if __name__ == "__main__":
	QrDecode().run()
