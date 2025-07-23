#!/usr/bin/env python3

from cortexutils.responder import Responder
from falconpy import OAuth2, Hosts

class CrowdstrikeFalconHosts(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.client_id = self.get_param("config.client_id")
        self.client_secret = self.get_param("config.client_secret")
        self.service = self.get_param("config.service", None)
        self.base_url = self.get_param("config.base_url", "https://api.crowdstrike.com")


    def run(self):
        Responder.run(self)
        hostname = self.get_param("data.data", None)
        #self.report({'message': f"Host {device_name}"})
        # Define the custom headers
        extra_headers = {
            "User-Agent": "strangebee-thehive/1.0"
        }
        auth = OAuth2(client_id=self.client_id, client_secret=self.client_secret, base_url=self.base_url)
        hosts = Hosts(auth_object=auth, ext_headers=extra_headers)
        
        # Search for the device ID using the hostname
        if self.service == "unhide_host":
            response = hosts.query_hidden_devices(filter=f"hostname:'{hostname}'")
        else:
            response = hosts.query_devices_by_filter(filter=f"hostname:'{hostname}'")
        if 200 <= response["status_code"] < 300:
            hosts_ids = response["body"]["resources"]
        else:
            return self.error(f"Error on getting device ID : {response['body']['errors']}")
            
        if hosts_ids:
            action_response = hosts.perform_action(action_name=self.service, ids=hosts_ids)
            if 200 <= action_response["status_code"] < 300:
                return self.report({'message': f"Operation {self.service} has been performed on {hostname} successfully: {action_response['body']['resources']}"})
            else:
                return self.error(f"Error on performing operation {self.service} on {hostname}: {action_response['body']['errors']}")
        else:
            return self.error(f"Host {hostname} not found.")
            

    def operations(self, raw):
        operations_list = []
        if self.service in ["contain", "hide_host", "detection_suppress"]: 
            operations_list.append(self.build_operation('AddTagToCase', tag=f'containment:{self.get_param("config.service", None)}={self.get_param("data.data", None)}'))
        return operations_list
    
if __name__ == '__main__':
    CrowdstrikeFalconHosts().run()
