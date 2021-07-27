#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from thehive4py.api import TheHiveApi
from panos import firewall
import panos.policies
import json

class Unblock_user(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.hostname_PaloAltoNGFW = self.get_param('config.Hostname_PaloAltoNGFW')
        self.User_PaloAltoNGFW = self.get_param('config.User_PaloAltoNGFW')
        self.Password_PaloAltoNGFW = self.get_param('config.Password_PaloAltoNGFW')
        self.name_security_rule = self.get_param('config.name_security_rule','TheHive Block external user')
        self.TheHive_instance = self.get_param('config.TheHive_instance')
        self.TheHive_API_key = self.get_param('config.TheHive_API_key', 'YOUR_KEY_HERE')
        self.api = TheHiveApi(self.TheHive_instance, self.TheHive_API_key)

    def run(self):
        self.instance_type = self.get_param('data._type')
        if self.instance_type == 'case_artifact':
                user = self.get_param('data.data')
        if self.instance_type == 'alert':
            alertId = self.get_param('data.id')
            response = self.api.get_alert(alertId)
            user=None
            user_list_alert=[]
            for i in list(response.json().get("artifacts")):
                if 'username' in str(i):
                    ioc = i.get("data")
                    for i in ioc:
                        if i == "[" or i == "]":
                            continue
                        else:
                            user_list_alert.append(i)
                    user="".join(user_list_alert)
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
            for n in data:
               if n.get('dataType') == 'username':
                   user=n.get('data')
        fw = firewall.Firewall(self.hostname_PaloAltoNGFW, api_username=self.User_PaloAltoNGFW, api_password=self.Password_PaloAltoNGFW)
        rulebase = panos.policies.Rulebase()
        fw.add(rulebase)
        current_security_rules =panos.policies.SecurityRule.refreshall(rulebase)
        user_list=[]
        rule_atrib=[]
        for i in current_security_rules:
            if i.about().get('name') == self.name_security_rule:
                rule_atrib = i.about()
                user_list=i.about().get("source_user")
        if user in user_list:
            user_list.remove(user)
        rule_atrib.update({"source_user": user_list})
        desired_rule_params = rule_atrib
        new_rule = panos.policies.SecurityRule(**desired_rule_params)
        rulebase.add(new_rule)
        new_rule.apply()
        self.report({'message': 'Responder successfully deleted %s from %s' % (user,self.name_security_rule)})
        fw.commit()

if __name__ == '__main__':
    Unblock_user().run()
