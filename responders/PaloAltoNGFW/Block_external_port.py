#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from thehive4py.api import TheHiveApi
from panos import firewall
import panos.objects
import re
import panos.policies
import json

class Block_port(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.hostname_PaloAltoNGFW = self.get_param('config.Hostname_PaloAltoNGFW')
        self.User_PaloAltoNGFW = self.get_param('config.User_PaloAltoNGFW')
        self.Password_PaloAltoNGFW = self.get_param('config.Password_PaloAltoNGFW')
        self.name_security_rule = self.get_param('config.Security_rule_for_block_port_external_communication','TheHive Block port for external communication')
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
               if n.get('dataType') == 'protocol':
                   protocol=n.get('data')
        fw = firewall.Firewall(self.hostname_PaloAltoNGFW, api_username=self.User_PaloAltoNGFW, api_password=self.Password_PaloAltoNGFW)
        panos.objects.ServiceObject.refreshall(fw)
        rulebase = panos.policies.Rulebase()
        fw.add(rulebase)
        current_security_rules =panos.policies.SecurityRule.refreshall(rulebase)
        if port not in str(fw.find(port, panos.objects.ServiceObject)):
            new_port_object = panos.objects.ServiceObject(port, protocol, description="TheHive Blocked port",destination_port=port)
            fw.add(new_port_object)
            new_port_object.create()    

            
        panos.objects.ServiceGroup.refreshall(fw)
        block_list = fw.find("TheHive Black list external port", panos.objects.ServiceGroup)
        if block_list != None:
            port_list = block_list.about().get('value')
            if port not in port_list:
                port_list.append(port)
                temp1 = panos.objects.ServiceGroup("TheHive Black list external port", value=port_list)
                fw.add(temp1)
                temp1.apply()
        elif block_list == None:
            temp1 = panos.objects.ServiceGroup("TheHive Black list external port", value=port)
            fw.add(temp1)
            temp1.apply()
        desired_rule_params = None
        for i in current_security_rules:
            if self.name_security_rule == str(i.about().get("name")):
                rule_atrib = i.about()
                temp_rule_atrib = rule_atrib.get("service")
                if "TheHive Black list external port" not in temp_rule_atrib:
                    temp_rule_atrib.append("TheHive Black list external port")
                    if "application-default" in temp_rule_atrib:
                        temp_rule_atrib.remove("application-default")
                    rule_atrib.update({"service": temp_rule_atrib})
                    desired_rule_params = rule_atrib
        new_rule = panos.policies.SecurityRule(**desired_rule_params)
        rulebase.add(new_rule)
        new_rule.apply()
        fw.commit()
        self.report({'message': 'Responder successfully added %s into TheHive Black list external port to %s' % (port,self.name_security_rule)})

if __name__ == '__main__':
    Block_port().run()
