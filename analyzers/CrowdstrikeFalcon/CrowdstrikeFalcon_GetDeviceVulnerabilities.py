#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.analyzer import Analyzer
from falconpy import OAuth2
from falconpy import Hosts
from falconpy import SpotlightVulnerabilities


class CrowdstrikeFalcon_GetDeviceVulnerabilities(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.client_id = self.get_param("config.client_id")
        self.client_secret = self.get_param("config.client_secret")
        self.vuln_fields = self.get_param("config.vuln_fields", [])
        self.base_url = self.get_param("config.base_url", "https://api.crowdstrike.com")


    def run(self):
        Analyzer.run(self)
        if self.data_type == 'hostname':
            try:
                # Define the custom header
                extra_headers = {
                    "User-Agent": "strangebee-thehive/1.0"
                }
                auth = OAuth2(client_id=self.client_id, client_secret=self.client_secret, base_url=self.base_url)
                hosts = Hosts(auth_object=auth, ext_headers=extra_headers)
                hostname = self.get_data()

                # Search for the device ID using the hostname
                response = hosts.query_devices_by_filter(filter=f"hostname:'{hostname}'")
                device_ids = response["body"]["resources"]

                # Check the response
                status_code = response["status_code"]
                if status_code != 200 :
                    self.error(f"No devices found with hostname: {hostname} -- {status_code}")

                if device_ids:
                    device_id = device_ids[0]
                    # Get detailed asset information using the device ID
                spotlight = SpotlightVulnerabilities(auth_object=auth, ext_headers=extra_headers)
                host_vulns = spotlight.query_vulnerabilities_combined(parameters={"filter": f"aid:'{device_id}'+status:!'closed'"})
                host_vulns = host_vulns["body"]["resources"]
                #print(host_vulns)
                vuln_details = []
                products_with_vulns = {}
                for vuln in host_vulns:
                    product_name = vuln["apps"][0]["product_name_normalized"]
                    vuln_id = vuln["id"]
                    
                    if product_name not in products_with_vulns:
                        products_with_vulns[product_name] = []
                    
                    products_with_vulns[product_name].append(vuln_id)
                for key, vuln_ids in products_with_vulns.items():
                    for vuln_id in vuln_ids:
                        request = spotlight.get_vulnerabilities(vuln_id)
                        data = request["body"]["resources"][0]
                        # Filter the dictionary
                        #filtered_data = {key: data[key] for key in top_10_keys if key in data}
                        filtered_data = self.filter_dict(data, self.vuln_fields)
                        vuln_details.append(filtered_data)
                self.report({"message": vuln_details})
            except Exception as e:
                    self.unexpectedError(e)
        else:
            self.notSupported()

    def filter_dict(self, d, keys):
        filtered = {}
        for key in keys:
            parts = key.split(".")
            if len(parts) == 3:
                main_key, sub_key, sub_sub_key = parts
                if main_key in d and sub_key in d[main_key]:
                    filtered.setdefault(main_key, {}).setdefault(sub_key, [])
                    for entity in d[main_key][sub_key]:
                        filtered[main_key][sub_key].append({sub_sub_key: entity[sub_sub_key]})
            elif len(parts) == 2:
                main_key, sub_key = parts
                if main_key in d and sub_key in d[main_key]:
                    filtered.setdefault(main_key, {})[sub_key] = d[main_key][sub_key]
            elif len(parts) == 1:
                main_key = parts[0]
                if main_key in d:
                    filtered[main_key] = d[main_key]
        return filtered

    def summary(self, raw):
        taxonomies = []
        level = "safe"
        namespace = "CSFalcon"
        predicate = "VulnDetails"

        count_vulns = len(raw["message"])
        if count_vulns > 0:
            level = "suspicious"
            for vuln in raw["message"]:
                        if vuln["cve"]["base_score"] >= 7:
                            level = "malicious"

        # Build summary
        taxonomies.append(
            self.build_taxonomy(
                level, namespace, predicate, str(count_vulns)
            )
        )
        return {"taxonomies": taxonomies}
    
    def artifacts(self, raw):
        artifacts = []
        #artifacts.append(self.build_artifact("ip",raw["external_ip"],tags=["hostname=" + raw["hostname"], "external_ip"]))
        return artifacts

    
if __name__ == "__main__":
    CrowdstrikeFalcon_GetDeviceVulnerabilities().run()
