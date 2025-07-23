#!/usr/bin/env python3

from cortexutils.responder import Responder
import requests
from falconpy import OAuth2, IOC
from datetime import datetime, timedelta
import re
from urllib.parse import urlparse

class CrowdstrikeFalconIOC(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.client_id = self.get_param("config.client_id")
        self.client_secret = self.get_param("config.client_secret")
        self.base_url = self.get_param("config.base_url", "https://api.crowdstrike.com")
        self.service = self.get_param("config.service", None)
        self.platform_list = self.get_param("config.platform_list", [])
        self.host_groups_list = self.get_param("config.host_groups_list", [])
        self.tags_list = self.get_param("config.tags_list", [])
        self.severity = self.get_param("config.severity", "informational")
        self.action = self.get_param("config.action", "detect")
        self.expiration_days = self.get_param("config.expiration_days", 0)
        self.retrodetect_flag = self.get_param("config.retrodetect_flag", False)
    
    def identify_and_extract(self, input_string):
        # Regular expressions for different types
        patterns = {
            "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
            "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
            "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
            "ipv4": re.compile(r"^(\d{1,3}\.){3}\d{1,3}$"),
            "ipv6": re.compile(r"^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)|(([0-9a-fA-F]{1,4}:){1,7}|:)(:([0-9a-fA-F]{1,4}|:)){1,7}$"),
            "domain": re.compile(r"^(?!:\/\/)([a-zA-Z0-9-_]+\.)*([a-zA-Z0-9-_]{2,})(\.[a-zA-Z]{2,11})$")
        }

        # Check if the input_string matches any of the patterns
        for key, pattern in patterns.items():
            if pattern.match(input_string):
                return key, input_string

        # Check if the input_string is a URL and extract the domain
        try:
            parsed_url = urlparse(input_string)
            if parsed_url.scheme and parsed_url.netloc:
                domain = parsed_url.netloc
                # Handle URLs with "www."
                if domain.startswith("www."):
                    domain = domain[4:]
                return "domain", domain
        except Exception as e:
            self.error(f"Error parsing URL: {e}")

        return None
    
    def run(self):
        if self.service == "addIOC":
            observable_value = self.get_param("data.data", None)
            ioc_type, ioc_value = self.identify_and_extract(observable_value)

            platform_list = self.platform_list
            tag_list = self.tags_list
            host_groups_list = self.host_groups_list
            severity = self.severity
            action = self.action

            ## If the analyzer is configured as prevent, it works only with hashes. So we revert to detect in that case.
            if ioc_type not in ["sha256", "sha1", "md5"] and action == "prevent":
                action = "detect"
            elif ioc_type not in ["sha256", "sha1", "md5"] and action == "allow":
                action = "no_action"
            
            # Calculate expiration date if specified
            expiration = None
            if self.expiration_days > 0:
                new_datetime = datetime.utcnow() + timedelta(days=self.expiration_days)
                expiration = new_datetime.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

            case_title = self.get_param("data.case.title", None, "Can't get case title")
            case_id = self.get_param("data.case.id", None, "Can't get case ID")
            description = f"Pushed from TheHive - {case_title} - {case_id}"

            # Define the custom headers
            extra_headers = {
                "User-Agent": "strangebee-thehive/1.0"
            }
            # Create the IOC service object
            auth = OAuth2(client_id=self.client_id, client_secret=self.client_secret, base_url=self.base_url)
            ioc = IOC(auth_object=auth, ext_headers=extra_headers)

            # Determine if the IOC applies globally or to specific host groups
            ioc_kwargs = {
                'action': action,
                'comment': None,
                'description': description,
                'expiration': expiration,
                'filename': None,
                'ignore_warnings': False,
                'platforms': platform_list,
                'retrodetects': self.retrodetect_flag,
                'severity': severity,
                'source': "TheHive",
                'tags': tag_list,
                'type': ioc_type,
                'value': ioc_value,
            }

            if "all" in host_groups_list:
                ioc_kwargs['applied_globally'] = True
            else:
                ioc_kwargs['host_groups'] = host_groups_list

            response = ioc.indicator_create(**ioc_kwargs)

            # Get the status code from the response
            status_code = response.get('status_code', None)
            if 200 <= status_code < 300:
                self.report({"message": f"{ioc_value} has been added to IoC Management as a {ioc_type} with action : {action}"})
            else:
                self.error(f"An error occurred: {str(status_code)} -- {response.get('body', 'No additional error information available')}")
        elif self.service == "removeIOC":
            # The value of the IOC to search for
            ioc_value = self.get_param("data.data", None)
            
            filter = f"_all:~'{ioc_value}'"


            # Define the custom headers
            extra_headers = {
                "User-Agent": "strangebee-thehive/1.0"
            }
            # Create the IOC service object
            auth = OAuth2(client_id=self.client_id, client_secret=self.client_secret, base_url=self.base_url)
            ioc = IOC(auth_object=auth, ext_headers=extra_headers)
            # Search for the IOC by value
            response = ioc.indicator_search(filter=filter,offset=0, limit=200)
                
            # Check if the search was successful
            status_code = response['status_code']
            if 200 <= status_code < 300:
                resources = response.get('body', {}).get('resources', [])
                if resources:
                    ioc_id = resources[0]
                    # Delete the IOC using the found ID
                    delete_response = ioc.indicator_delete(ids=ioc_id)
                    delete_status_code = delete_response['status_code']
                    if 200 <= delete_status_code < 300:
                        message =  f"IOC {ioc_value} deleted successfully. IOC ID : {ioc_id}"
                    else:
                        self.error(f"Failed to delete IOC: {delete_response}")
                else:
                    self.error(f"IOC {ioc_value} not found. Query filter: {filter}")
            else:
               self.error(f"Error searching for IOC: {response}")
            self.report({"message": message})



if __name__ == '__main__':
    CrowdstrikeFalconIOC().run()
