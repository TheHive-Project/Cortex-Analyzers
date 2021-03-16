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
        self.name_external_Service_Group = self.get_param('config.Service_group_for_unblock_external_port','TheHive Black list external port')
        self.thehive_instance = self.get_param('config.thehive_instance')
        self.thehive_api_key = self.get_param('config.thehive_api_key', 'YOUR_KEY_HERE')
        self.api = TheHiveApi(self.thehive_instance, self.thehive_api_key)

    def run(self):
        self.instance_type = self.get_param('data._type')
        if self.instance_type == 'case_artifact':
                port = self.get_param('data.data')
        if self.instance_type == 'alert':
            alertId = self.get_param('data.id')
            response = self.api.get_alert(alertId)
            data_list=[]
            data=None
            for i in response.json().get("artifacts"):
                if "'port'," in str(i):
                   data_list.append(i.get("data"))
                elif "'protocol'," in str(i):
                   data_list.append(i.get("data"))
                data=" ".join(data_list)
            protocol=re.findall(r'[a-z]+',str(data)); protocol=str("".join(protocol)).lower()
            port=re.findall(r'[0-9]+',str(data)); port="".join(port)
        if self.instance_type == 'case':
            import requests
            case_id = self.get_param('data._id')
            payload = {
                "query": { "_parent": { "_type": "case", "_query": { "_id": case_id } } },
                "range": "all"
            }
            headers = { 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(self.thehive_api_key) }
            thehive_api_url_case_search = '{}/api/case/artifact/_search'.format(self.thehive_instance)
            r = requests.post(thehive_api_url_case_search, data=json.dumps(payload), headers=headers)
            if r.status_code != requests.codes.ok:
                self.error(json.dumps(r.text))
            a=None
            data = r.json()
            for n in data:
               if n.get('dataType') == 'port':
                   port=n.get('data')
        fw = firewall.Firewall(self.hostname_PaloAltoNGFW, api_username=self.User_PaloAltoNGFW, api_password=self.Password_PaloAltoNGFW)
        panos.objects.ServiceGroup.refreshall(fw)
        block_list = fw.find(self.name_external_Service_Group, panos.objects.ServiceGroup)
        port_list = block_list.about().get('value')    
        if port in port_list:
            port_list.remove(port)
            temp1 = panos.objects.ServiceGroup(self.name_external_Service_Group, value=port_list)
            fw.add(temp1)
            temp1.apply()
        
        panos.objects.ServiceObject.refreshall(fw)
        
        self.report({'message': 'Responder successfully deleted %s from %s' % (port,self.name_external_Service_Group)})
        fw.commit()

if __name__ == '__main__':
    Unblock_port().run()
