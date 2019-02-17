#!/usr/bin/python2
# -*- coding: utf-8 -*-

import requests
import re
import json
import traceback

from cortexutils.responder import Responder
from requests.auth import HTTPBasicAuth

class FalconCustomIOC(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.falconapi_url = self.get_param(
            'config.falconapi_url', None, "Falcon API URL (e.g.:https://falconapi.crowdstrike.com/indicators/entities/iocs/v1)")
        self.apiuser = self.get_param(
            'config.falconapi_user', None, "Falcon query api key missing")
        self.apikey = self.get_param(
            'config.falconapi_key', None, "Falcon query api key missing")

    def run(self):
        try:
                Responder.run(self)
                ioctypes = {"hash": "sha256", "sha256": "sha256", "md5": "md5", "sha1": "sha1",
                    "ip": "ipv4", "ip6": "ipv6", "ipv6": "ipv6", "domain": "domain", "url": "domain"}
                data_type = self.get_param('data.dataType')
                if not data_type in ioctypes:
                    self.error("Unsupported IOC type")
                    return
		ioc = self.get_param('data.data', None, 'No IOC provided')
                if data_type == "url":
                        match = re.match(r"(http:\/\/|https:\/\/)?([\w\d\-\.]{0,256}).*", ioc)
                        if match is None or match.group(2) is None:
                            self.error("Could not parse domain from URL")
                            return
                        else:
            			ioc=match.group(2)
		description = self.get_param('data.case.title',None,"Can't get case title")
		description = str(description).encode('utf-8')[:128]
		postdata=json.dumps([{"type": ioctypes[data_type], "value": ioc.strip(), "policy": "detect", "description": description, "share_level": "red", "source": "Cortex - FalconCustomIOC ["+description+"]", "expiration_days": 30}])
		response=requests.post(self.falconapi_url,data=postdata,headers={"Content-Type":"application/json"},auth=HTTPBasicAuth(self.apiuser,self.apikey))
		json_response = json.loads(response.text)
		if json_response["errors"]:
			self.error(str(json_response["errors"]))
			return
		else:
			self.report({'message': ioc+" Submitted to Crowdstrike Falcon custom IOC api","api_response":json_response})
	except Exception as ex:
		self.error(traceback.format_exc())


    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='CrowdStrike:Custom IOC Uploaded')]
if __name__ == '__main__':
    FalconCustomIOC().run()

