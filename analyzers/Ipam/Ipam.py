#!/usr/bin/env python3
# -*- coding: utf-8 -*

import requests
import json
from requests.auth import HTTPBasicAuth
from cortexutils.analyzer import Analyzer

class Ipam(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.host = self.get_param(
            'config.host', None, 'The IPAM address is missing')
        self.app_name = self.get_param(
            'config.app_name', None, 'The IPAM appname is missing')
        self.password = self.get_param(
            'config.password', None, 'The IPAM password is missing')
        self.username = self.get_param(
            'config.username', None, 'The IPAM username is missing')

    def summary(self, raw):
        
        taxonomies = []
        
        if raw.get('info', None) is None:

            if raw.get('hostname', None) is not None \
                and raw.get('hostname', None) != 'null':
                taxonomies.append(self.build_taxonomy("info", "IP", "hostname", raw['hostname']))

            if raw.get('description', None) is not None \
                and raw.get('description', None) != 'null':
                taxonomies.append(self.build_taxonomy("info", "Ipam", "description", raw['description']))

            if raw.get('firewallAddressObject', None) is not None \
                and raw.get('firewallAddressObject', None) != 'null':
                taxonomies.append(self.build_taxonomy("info", "Ipam", "firewallAddressObject", raw['firewallAddressObject']))

            if raw.get('vlan_description', None) is not None \
                and raw.get('vlan_description', None) != 'null':
                taxonomies.append(self.build_taxonomy("info", "Ipam", "vlan", raw['vlan_description']))
            
            if raw.get('location', None) is not None \
                and raw.get('location', None) != 'null':
                taxonomies.append(self.build_taxonomy("info", "Ipam", "location", raw['location']))
            
            if raw.get('vlan_calculation', None) is not None \
                and raw['vlan_calculation'].get('Subnet bitmask', None) \
                and raw['vlan_calculation'].get('Subnet bitmask', None) != 'null':
                taxonomies.append(self.build_taxonomy("info", "Ipam", "CIDR", f"/{raw['vlan_calculation']['Subnet bitmask']}"))
    
        else:
            taxonomies.append(self.build_taxonomy("info", "Ipam", "message", raw['info']))
        
        return {"taxonomies": taxonomies}

    def token(self):
        r = requests.post(
            f"{self.host}/api/{self.app_name}/user/",
            auth=HTTPBasicAuth(
                self.username, self.password)
        )
        if r.status_code in [200, 201, 202, 302, 304]:
            return r.json()
        else:
            self.error('Unable to get Token, check credentials')

    def run(self):
        Analyzer.run(self)

        data = self.get_param('data', None, 'Data is missing')

        if self.data_type != 'ip':
            self.error('Invalid data type')

        token = self.token()

        if token is not None:
            r = requests.get(
                f"{self.host}/api/{self.app_name}/addresses/search/{data}",
                headers={
                    "token": token['data']['token']
                }
            )
            if r.status_code in [200, 201, 202, 302, 304]:
                if 'Address not found' not in str(r.content):

                    ipinfo = r.json()['data'][0]

                    r = requests.get(
                        f"{self.host}/api/{self.app_name}/subnets/{ipinfo['subnetId']}",
                        headers={
                            "token": token['data']['token']
                        }
                    )

                    if r.status_code in [200, 201, 202, 302, 304]:
                        ipinfo.update({
                            "vlan_description": r.json()['data']['description'],
                            "vlan_calculation": r.json()['data']['calculation'],
                        })

                    self.report(ipinfo)

                else:
                    self.report({
                        "info": f'The IP {data} does not exist in IPAM'
                    })

            else:
                self.error(f'Unable to connect to IPAM searching for IP {data}')
        

if __name__ == '__main__':
    Ipam().run()
