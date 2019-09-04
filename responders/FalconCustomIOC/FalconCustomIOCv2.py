#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
import re
import json
import traceback

from cortexutils.responder import Responder
from requests.auth import HTTPBasicAuth
from FalconAuth import FalconAuth


def cortexinputbug():
    import sys
    if len(sys.argv) > 1:
        try:
            sys.stdin = open(sys.argv[1]+"/input/input.json")
        except:
            with open("/tmp/responder_error", "w+") as e:
                e.write(traceback.format_exc())


class FalconCustomIOC(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.falconapi_url = "https://api.crowdstrike.com/indicators/entities/iocs/v1"
        self.clientid = self.get_param(
            'config.clientid', None, "Crowdstrike API oauth2 client id missing")
        self.clientsecret = self.get_param(
            'config.clientsecret', None, "Crowdstrike API oauth2 client secret missing")
        self.auth = FalconAuth(self.clientid, self.clientsecret)

    def run(self):
        try:
            Responder.run(self)
            ioctypes = {"hash": u"sha256", "sha256": u"sha256", "md5": u"md5", "sha1": u"sha1",
                        "ip": u"ipv4", "ip6": u"ipv6", "ipv6": u"ipv6", "domain": u"domain", "url": u"domain"}
            data_type = self.get_param('data.dataType')
            if not data_type in ioctypes:
                self.error("Unsupported IOC type")
                raise
            ioc = self.get_param('data.data', None, 'No IOC provided')
            if data_type == "url":
                match = re.match(
                    r"(http:\/\/|https:\/\/)?([\w\d\-\.]{0,256}).*", ioc)
                if match is None or match.group(2) is None:
                    self.error("Could not parse domain from URL")
                    raise
                else:
                    ioc = match.group(2)
            description = self.get_param(
                'data.case.title', None, "Can't get case title")
            description = u"{}".format(description.encode('utf-8')[:128])
            postdata = json.dumps([{"type": ioctypes[data_type], "value": ioc.strip(), "policy": u"detect", "description": description,
                                    "share_level": u"red", "source": u"Cortex - FalconCustomIOC [{}]".format(description), "expiration_days": 30}])
            response = requests.post(self.falconapi_url, data=postdata, headers={
                                     "Content-Type": "application/json", "Authorization": "Bearer {}".format(self.auth.getToken())})
            json_response = json.loads(response.text)
            if json_response["errors"]:
                self.error(str(json_response["errors"]))
                raise
            else:
                self.report(
                    {'message': ioc+" Submitted to Crowdstrike Falcon custom IOC api", "api_response": json_response})
        except Exception as ex:
            self.error(traceback.format_exc())

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='CrowdStrike:Custom IOC Uploaded')]


if __name__ == '__main__':
    cortexinputbug()
    FalconCustomIOC().run()
