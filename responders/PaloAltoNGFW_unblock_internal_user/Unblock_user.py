#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from thehive4py.api import TheHiveApi
from panos import firewall
import panos.policies

class Unblock_user(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.hostname_PaloAltoNGFW = self.get_param('config.Hostname_PaloAltoNGFW')
        self.User_PaloAltoNGFW = self.get_param('config.User_PaloAltoNGFW')
        self.Password_PaloAltoNGFW = self.get_param('config.Password_PaloAltoNGFW')
        self.name_security_rule = self.get_param('config.name_security_rule','Block user internal communication')
        self.thehive_instance = self.get_param('config.thehive_instance')
        self.thehive_api_key = self.get_param('config.thehive_api_key', 'YOUR_KEY_HERE')
        self.api = TheHiveApi(self.thehive_instance, self.thehive_api_key)

    def run(self):
        alertId = self.get_param('data.id')
        response = self.api.get_alert(alertId)
        user=None
        user_list_alert=[]
        for i in list(response.json().get("artifacts")):
            if 'user' in str(i):
                ioc = i.get("data")
                for i in ioc:
                    if i == "[" or i == "]":
                        continue
                    else:
                        user_list_alert.append(i)
                user="".join(user_list_alert)
        fw = firewall.Firewall(self.hostname_PaloAltoNGFW, api_username=self.User_PaloAltoNGFW, api_password=self.Password_PaloAltoNGFW)
        rulebase = panos.policies.Rulebase()
        fw.add(rulebase)
        current_security_rules =panos.policies.SecurityRule.refreshall(rulebase)
        user_list=[]
        for i in current_security_rules:
            if i.about().get('name') == self.name_security_rule:
                user_list=i.about().get("source_user")
        if user in user_list:
            user_list.remove(user)
        desired_rule_params = {
            "name": self.name_security_rule,
            "description": "Block user internal communication",
            "type": "intrazone",
            "action": "deny",
            'source_user': user_list
            }
        new_rule = panos.policies.SecurityRule(**desired_rule_params)
        rulebase.add(new_rule)
        new_rule.apply()
        self.report({'message': 'message sent'})

if __name__ == '__main__':
    Unblock_user().run()
