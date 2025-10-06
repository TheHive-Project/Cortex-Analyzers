#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.analyzer import Analyzer
from falconpy import OAuth2
from falconpy import Hosts
from falconpy import Discover


class CrowdstrikeFalcon_getDeviceDetails(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.client_id = self.get_param("config.client_id")
        self.client_secret = self.get_param("config.client_secret")
        self.base_url = self.get_param("config.base_url", "https://api.crowdstrike.com")


    def run(self):
        Analyzer.run(self)
        if self.data_type == 'hostname':
            try:
                auth = OAuth2(client_id=self.client_id, client_secret=self.client_secret, base_url=self.base_url)
                # Define the custom header
                extra_headers = {
                    "User-Agent": "strangebee-thehive/1.0"
                }
                hosts = Hosts(auth_object=auth, ext_headers=extra_headers)
                hostname = self.get_data()

                # Search for the device ID using the hostname
                response = hosts.query_devices_by_filter(filter=f"hostname:'{hostname}'")
                if 200 <= response["status_code"] < 300:
                    device_ids = response["body"]["resources"]
                else:
                    return self.error(f"Error on getting device ID : {response['body']['errors']}")

                if device_ids:
                    device_id = device_ids[0]
                    # Get detailed asset information using the device ID
                    device_info_response = hosts.get_device_details(ids=device_id)
                    status_code = response["status_code"]
                    if 200 <= device_info_response["status_code"] < 300:
                        device_info = device_info_response["body"]["resources"][0]
                        return self.report(device_info)
                    else:
                        return self.error(f"Something went wrong when getting device details {device_info_response['body']['errors']}")
            except Exception as e:
                    self.unexpectedError(e)
        else:
            self.notSupported()

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "CSFalcon"
        predicate = "DeviceInfo"
        values = []
        values.append(f"{raw['system_manufacturer']}-{raw['system_product_name']}")
        values.append(f"OS={raw['os_version']}-{raw['os_build']}")
        values.append(f"Last_login_user : {raw['last_login_user']}")
        values.append(f"AgentRFM: {raw['reduced_functionality_mode']}")

        # Build summary
        for value in values:
            if "AgentRFM" in value and value == "AgentRFM: no":
                level = "safe"
            elif "AgentRFM" in value and value != "AgentRFM: no":
                level = "suspicious"
            taxonomies.append(
                self.build_taxonomy(
                    level, namespace, predicate, value
                )
            )
        return {"taxonomies": taxonomies}
    
    def artifacts(self, raw):
        artifacts = []
        artifacts.append(self.build_artifact("ip",raw["external_ip"],tags=["hostname=" + raw["hostname"], "external_ip"]))
        return artifacts

    
if __name__ == "__main__":
    CrowdstrikeFalcon_getDeviceDetails().run()
