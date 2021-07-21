#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from thehive4py.api import TheHiveApi
from panos import firewall
import panos.objects
import panos.policies
import re
import json

class Block_port(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.hostname_PaloAltoNGFW = self.get_param('config.Hostname_PaloAltoNGFW')
        self.User_PaloAltoNGFW = self.get_param('config.User_PaloAltoNGFW')
        self.Password_PaloAltoNGFW = self.get_param('config.Password_PaloAltoNGFW')
        self.name_security_rule = self.get_param('config.Security_rule_for_blocking_port_internal_communication','TheHive Block port for internal communication')
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
        panos.objects.ServiceObject.refreshall(fw)
        rulebase = panos.policies.Rulebase()
        fw.add(rulebase)
        current_security_rules =panos.policies.SecurityRule.refreshall(rulebase)
        if f"thehive-{port}-{protocol}" not in str(fw.find(f"thehive-{port}-{protocol}", panos.objects.ServiceObject)):
            new_port_object = panos.objects.ServiceObject(f"thehive-{port}-{protocol}", protocol, description="TheHive Blocked port",destination_port=port)
            fw.add(new_port_object)
            new_port_object.create()    

            
        panos.objects.ServiceGroup.refreshall(fw)
        block_list = fw.find("TheHive Block list for internal port communication", panos.objects.ServiceGroup)
        if block_list != None:
            port_list = block_list.about().get('value')
            if f"thehive-{port}-{protocol}" not in port_list:
                port_list.append(f"thehive-{port}-{protocol}")
                temp1 = panos.objects.ServiceGroup("TheHive Block list for internal port communication", value=port_list)
                fw.add(temp1)
                temp1.apply()
        elif block_list == None:
            temp1 = panos.objects.ServiceGroup("TheHive Block list for internal port communication", value=f"thehive-{port}-{protocol}")
            fw.add(temp1)
            temp1.apply()
        desired_rule_params = None
        for i in current_security_rules:
            if self.name_security_rule == i.about().get("name"):
                rule_atrib = i.about()
                temp_rule_atrib = rule_atrib.get("service")
                if "TheHive Block list for internal port communication" not in temp_rule_atrib:
                    temp_rule_atrib.append("TheHive Block list for internal port communication")
                    if "application-default" in temp_rule_atrib:
                        temp_rule_atrib.remove("application-default")
                    rule_atrib.update({"service": temp_rule_atrib})
                    desired_rule_params = rule_atrib
                else:
                    desired_rule_params = rule_atrib
        new_rule = panos.policies.SecurityRule(**desired_rule_params)
        rulebase.add(new_rule)
        new_rule.apply()
        fw.commit()
        self.report({'message': 'Responder successfully added %s into TheHive Block list for internal port communication from %s' % (port,self.name_security_rule)})

if __name__ == '__main__':
    Block_port().run()
