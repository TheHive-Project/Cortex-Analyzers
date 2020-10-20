#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from thehive4py.api import TheHiveApi
from panos import firewall
import panos.objects
import re
class Block_port(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.hostname_PaloAltoNGFW = self.get_param('config.Hostname_PaloAltoNGFW')
        self.User_PaloAltoNGFW = self.get_param('config.User_PaloAltoNGFW')
        self.Password_PaloAltoNGFW = self.get_param('config.Password_PaloAltoNGFW')
        self.name_external_Service_Group = self.get_param('config.name_external_Service_Group')
        self.thehive_instance = self.get_param('config.thehive_instance')
        self.thehive_api_key = self.get_param('config.thehive_api_key', 'YOUR_KEY_HERE')
        self.api = TheHiveApi(self.thehive_instance, self.thehive_api_key)

    def run(self):
        alertId = self.get_param('data.id')
        response = self.api.get_alert(alertId)
        data_list=[]
        data=None
        for i in response.json().get("artifacts"):
            if "'port'," in str(i):
               ioc = i.get("data")
               data_list.append(i.get("data"))
            elif "'protocol'," in str(i):
               ioc = i.get("data")
               data_list.append(i.get("data"))
            data=" ".join(data_list)
        protocol=re.findall(r'[a-z]+',str(data)); protocol=str("".join(protocol)).lower()
        port=re.findall(r'[0-9]+',str(data)); port="".join(port)
        fw = firewall.Firewall(self.hostname_PaloAltoNGFW, api_username=self.User_PaloAltoNGFW, api_password=self.Password_PaloAltoNGFW)
        panos.objects.ServiceObject.refreshall(fw)
        if port not in str(fw.find(port, panos.objects.ServiceObject)):
            new_port_object = panos.objects.ServiceObject(port, protocol, description="Blocked port",destination_port=port)
            fw.add(new_port_object)
            new_port_object.create()    

            
        panos.objects.ServiceGroup.refreshall(fw)
        block_list = fw.find(self.name_external_Service_Group, panos.objects.ServiceGroup)
        port_list = block_list.about().get('value')
        if port not in port_list:
            port_list.append(port)
            temp1 = panos.objects.ServiceGroup(self.name_external_Service_Group, value=port_list)
            fw.add(temp1)
            temp1.apply()
        self.report({'message': 'message sent'})

if __name__ == '__main__':
    Block_port().run()
