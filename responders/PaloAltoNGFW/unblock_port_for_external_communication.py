#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from thehive4py.api import TheHiveApi
from panos import firewall
import panos.objects
import re
import json

class Unblock_port(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.hostname_PaloAltoNGFW = self.get_param('config.Hostname_PaloAltoNGFW')
        self.User_PaloAltoNGFW = self.get_param('config.User_PaloAltoNGFW')
        self.Password_PaloAltoNGFW = self.get_param('config.Password_PaloAltoNGFW')
        self.name_external_Service_Group = self.get_param('config.Service_group_for_unblock_external_port','TheHive Block list for external port communication')
        self.TheHive_instance = self.get_param('config.TheHive_instance')
        self.TheHive_API_key = self.get_param('config.TheHive_API_key', 'YOUR_KEY_HERE')
        self.api = TheHiveApi(self.TheHive_instance, self.TheHive_API_key)

    def run(self):
        self.instance_type = self.get_param('data._type')
        if self.instance_type == 'case_artifact':
                data = self.get_param('data.data')
                port=str(data).split('-')[0]
                protocol=str(data).split('-')[1]
                protocol=re.findall(r'[a-z]+',str(protocol)); protocol=str("".join(protocol)).lower()
                port=re.findall(r'[0-9]+',str(port)); port="".join(port)
        if self.instance_type == 'alert':
            alertId = self.get_param('data.id')
            response = self.api.get_alert(alertId)
            data_list=[]
            data=None
            for i in response.json().get("artifacts"):
                if "'port-protocol'," in str(i):
                   data_list.append(i.get("data"))
                port=str(data_list).split('-')[0]
                protocol=str(data_list).split('-')[1]
            protocol=re.findall(r'[a-z]+',str(protocol)); protocol=str("".join(protocol)).lower()
            port=re.findall(r'[0-9]+',str(port)); port="".join(port)
        if self.instance_type == 'case':
            import requests
            case_id = self.get_param('data._id')
            payload = {
                "query": { "_parent": { "_type": "case", "_query": { "_id": case_id } } },
                "range": "all"
            }
            headers = { 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(self.TheHive_API_key) }
            thehive_api_url_case_search = '{}/api/case/artifact/_search'.format(self.TheHive_instance)
            r = requests.post(thehive_api_url_case_search, data=json.dumps(payload), headers=headers)
            if r.status_code != requests.codes.ok:
                self.error(json.dumps(r.text))
            a=None
            data = r.json()
            data_list=[]
            for n in data:
               if "'port-protocol'," in str(n):
                   data_list.append(n.get("data"))
               port=str(data_list).split('-')[0]
               protocol=str(data_list).split('-')[1]
            protocol=re.findall(r'[a-z]+',str(protocol)); protocol=str("".join(protocol)).lower()
            port=re.findall(r'[0-9]+',str(port)); port="".join(port)
        fw = firewall.Firewall(self.hostname_PaloAltoNGFW, api_username=self.User_PaloAltoNGFW, api_password=self.Password_PaloAltoNGFW)
        panos.objects.ServiceGroup.refreshall(fw)
        block_list = fw.find(self.name_external_Service_Group, panos.objects.ServiceGroup)
        port_list = block_list.about().get('value')    
        if f"thehive-{port}-{protocol}" in port_list:
            port_list.remove(f"thehive-{port}-{protocol}")
            temp1 = panos.objects.ServiceGroup(self.name_external_Service_Group, value=port_list)
            fw.add(temp1)
            temp1.apply()
        
        panos.objects.ServiceObject.refreshall(fw)
        
        self.report({'message': 'Responder successfully deleted %s from %s' % (f"thehive-{port}-{protocol}",self.name_external_Service_Group)})
        fw.commit()

if __name__ == '__main__':
    Unblock_port().run()
