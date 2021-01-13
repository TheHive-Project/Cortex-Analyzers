#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from thehive4py.api import TheHiveApi
from panos import firewall
import panos.objects
import panos.policies
import json

class Block_ip(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.hostname_PaloAltoNGFW = self.get_param('config.Hostname_PaloAltoNGFW')
        self.User_PaloAltoNGFW = self.get_param('config.User_PaloAltoNGFW')
        self.Password_PaloAltoNGFW = self.get_param('config.Password_PaloAltoNGFW')
        self.name_security_rule = self.get_param('config.name_security_rule','TheHive Block external IP address')
        self.thehive_instance = self.get_param('config.thehive_instance')
        self.thehive_api_key = self.get_param('config.thehive_api_key', 'YOUR_KEY_HERE')
        self.api = TheHiveApi(self.thehive_instance, self.thehive_api_key)

    def run(self):
        self.instance_type = self.get_param('data._type')
        if self.instance_type == 'case_artifact':
                ioc = self.get_param('data.data')
        if self.instance_type == 'alert':
            alertId = self.get_param('data.id')
            response = self.api.get_alert(alertId)
            ioc=None
            ioc_clear=[]
            for i in list(response.json().get("artifacts")):
                if 'ip' in str(i):
                    ioc = i.get("data")
                    for i in ioc:
                        if i == "[" or i == "]":
                            continue
                        else:
                            ioc_clear.append(i)
                    ioc="".join(ioc_clear)
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
               if n.get('dataType') == 'ip':
                   ioc=n.get('data')
        fw = firewall.Firewall(self.hostname_PaloAltoNGFW, api_username=self.User_PaloAltoNGFW, api_password=self.Password_PaloAltoNGFW)
        panos.objects.AddressObject.refreshall(fw)
        rulebase = panos.policies.Rulebase()
        fw.add(rulebase)
        current_security_rules =panos.policies.SecurityRule.refreshall(rulebase)
        if ioc not in str(fw.find(ioc, panos.objects.AddressObject)):
            new_ioc_object = panos.objects.AddressObject(ioc, ioc, description="TheHive Blocked ip address")
            fw.add(new_ioc_object)
            new_ioc_object.create()        
        panos.objects.AddressGroup.refreshall(fw)
        block_list = fw.find("TheHive Black list external IP", panos.objects.AddressGroup)
        if block_list != None:
            ioc_list = block_list.about().get('static_value')
            if ioc not in ioc_list:
                ioc_list.append(ioc)
                temp1 = panos.objects.AddressGroup("TheHive Black list external IP", static_value=ioc_list)
                fw.add(temp1)
                temp1.apply()
        elif block_list == None:
            temp1 = panos.objects.AddressGroup("TheHive Black list external IP", static_value=ioc)
            fw.add(temp1)
            temp1.apply()
        desired_rule_params = None
        for i in current_security_rules:
            if self.name_security_rule == i.about().get("name"):
                rule_atrib = i.about()
                temp_rule_atrib = rule_atrib.get("destination")
                if "TheHive Black list external IP" not in temp_rule_atrib:
                    temp_rule_atrib.append("TheHive Black list external IP")
                    if "any" in temp_rule_atrib:
                        temp_rule_atrib.remove("any")
                    rule_atrib.update({"destination": temp_rule_atrib})
                    desired_rule_params = rule_atrib
                else:
                    desired_rule_params = rule_atrib
        new_rule = panos.policies.SecurityRule(**desired_rule_params)
        rulebase.add(new_rule)
        new_rule.apply()
        self.report({'message': 'Responder comlited, added %s into TheHive Black list external IP from %s' % (ioc,self.name_security_rule)})
if __name__ == '__main__':
    Block_ip().run()
