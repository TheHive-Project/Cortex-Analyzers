#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
import json
import ipaddress

from cortexutils.responder import Responder
from cortexutils.extractor import Extractor
from falconpy import OAuth2, IOC
from dateutil.relativedelta import relativedelta
from datetime import datetime


class FalconCustomIOC(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.falconapi_endpoint = self.get_param(
            "config.falconapi_endpoint", None, "Falcon API Endpoint: US-1 | US-2 | US-GOV-1 | EU-1",
        )
        self.falconapi_clientid = self.get_param(
            "config.falconapi_clientid", None, "Falcon clientid missing"
        )
        self.falconapi_key = self.get_param(
            "config.falconapi_key", None, "Falcon api key missing"
        )
        self.domain_block_expiration_days = self.get_param(
            "config.domain_block_expiration_days", 30
        )
        self.ip_block_expiration_days = self.get_param(
            "config.ip_block_expiration_days", 30
        )
        self.hash_block_expiration_days = self.get_param(
            "config.hash_block_expiration_days", 30
        )
        self.action_to_take = self.get_param(
            "config.action_to_take", "detect"
        )
        self.severity_level = self.get_param(
            "config.severity_level", "high"
        )
        self.tag_added_to_cs = self.get_param(
            "config.tag_added_to_cs", "Cortex Incident - FalconCustomIOC"
        )
        self.tag_added_to_thehive = self.get_param(
            "config.tag_added_to_thehive", "CrowdStrike:Custom IOC Uploaded"
        )

    def run(self):
        try:
            Responder.run(self)
            ioctypes = {
                "hash": "sha256",
                "sha256": "sha256",
                "md5": "md5",
                "ip": "ipv4",
                "ipv4": "ipv4",
                "ip6": "ipv6",
                "ipv6": "ipv6",
                "domain": "domain",
                "url": "domain",
            }

            data_type = self.get_param("data.dataType")
            if not data_type in ioctypes:
                self.error("Unsupported IOC type")
                return False
            ioc = self.get_param("data.data", None, "No IOC provided")

            if data_type == "url":
                match = re.match(r"(http:\/\/|https:\/\/)?([\w\-\.]{0,256}).*", ioc)
                if match is None or match.group(2) is None:
                    self.error("Could not parse iocs from URL")
                    return False
                else:
                    ioc = match.group(2)
                    data_type = Extractor().check_string(ioc)

            if data_type == "ip":
                try:
                    ip_check = ipaddress.ip_address(ioc)
                except Exception as e:
                    self.error(f"Could not check IP type from IOC : {e}")
                    return False
                if isinstance(ip_check, ipaddress.IPv6Address):
                    data_type = "ipv6"
                elif isinstance(ip_check, ipaddress.IPv4Address):
                    data_type = "ipv4"
                else:
                    self.error("Could not determine IP type from IOC")
                    return False

            if data_type == "hash":
                if len(ioc) == 32:
                    data_type = "md5"
                elif len(ioc) == 40:
                    self.error("Unsupported IOC type")
                    return False
                elif len(ioc) == 64:
                    data_type = "sha256"

            if data_type in ("fqdn", "domain"):
                expiration_date = datetime.today() + relativedelta(days=self.domain_block_expiration_days)
            elif data_type in ("ip", "ipv4", "ipv6", "ip6"):
                expiration_date = datetime.today() + relativedelta(days=self.ip_block_expiration_days)
            elif data_type in ("hash", "sha256", "md5"):
                expiration_date = datetime.today() + relativedelta(days=self.hash_block_expiration_days)
            expiration = expiration_date.strftime("%Y-%m-%dT%H:%M:%SZ")

            incident_title = self.get_param("data.case.title", None, "Can't get case title").encode("utf-8")[:128]

            auth = OAuth2(
                client_id=self.falconapi_clientid,
                client_secret=self.falconapi_key,
                base_url=self.falconapi_endpoint
            )
            
            falcon_api = IOC(auth_object=auth)
            response = falcon_api.indicator_create(action=self.action_to_take,
                                                   applied_globally=True,
                                                   comment="TheHive IOC incident",
                                                   description=incident_title.decode("utf-8"),
                                                   expiration=expiration,
                                                   filename="",
                                                   ignore_warnings=False,
                                                   platforms='mac,windows,linux',
                                                   severity=self.severity_level,
                                                   source="Cortex - FalconCustomIOC [" + incident_title.decode("utf-8") + "]",
                                                   tags=self.tag_added_to_cs,
                                                   type=ioctypes[data_type],
                                                   value=ioc.strip()
                                                   )
            
            response_error = str(response['body']['errors'])
            response_ressources = str(response['body']['resources'])

            if response['body']['errors'] is None:
                self.report(
                    {"message": f"{ioc} successuflly submitted to Crowdstrike Falcon custom IOC api - status code: {response['status_code']}"}
                )
            elif 'Duplicate type' in response_ressources:
                self.error(f"Not submitted because of duplicated entry - {ioc} already found on your Falcon CustomIOC database")
                return False
            else:
                self.error(f"Error: unable to complete action - received {response['status_code']} status code from FalconIOC API with the following message: {response_error}")
                return False

        except Exception as ex:
            self.error(f"Unable to send IOC to FalconCustomIOC API: {ex}")
            return False
        return True

    def operations(self, raw):
        return [
            self.build_operation(
                "AddTagToArtifact", tag=self.tag_added_to_thehive
            )
        ]

if __name__ == "__main__":
    FalconCustomIOC().run()