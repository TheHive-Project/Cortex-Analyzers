#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from thehive4py.api import TheHiveApi
from panos import firewall
import panos.objects
import json

class Unblock_ip(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.hostname_PaloAltoNGFW = self.get_param('config.Hostname_PaloAltoNGFW')
        self.User_PaloAltoNGFW = self.get_param('config.User_PaloAltoNGFW')
        self.Password_PaloAltoNGFW = self.get_param('config.Password_PaloAltoNGFW')
        self.name_internal_Address_Group = self.get_param('config.Address_group_for_unblock_internal_IP_address',"TheHive Block list internal IP address")
        self.TheHive_instance = self.get_param('config.TheHive_instance')
        self.TheHive_API_key = self.get_param('config.TheHive_API_key', 'YOUR_KEY_HERE')
        self.api = TheHiveApi(self.TheHive_instance, self.TheHive_API_key)

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
            headers = { 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(self.TheHive_API_key) }
            thehive_api_url_case_search = '{}/api/case/artifact/_search'.format(self.TheHive_instance)
            r = requests.post(thehive_api_url_case_search, data=json.dumps(payload), headers=headers)
            if r.status_code != requests.codes.ok:
                self.error(json.dumps(r.text))
            a=None
            data = r.json()
            for n in data:
               if n.get('dataType') == 'ip':
                   ioc=n.get('data')
        fw = firewall.Firewall(self.hostname_PaloAltoNGFW, api_username=self.User_PaloAltoNGFW, api_password=self.Password_PaloAltoNGFW)
        panos.objects.AddressGroup.refreshall(fw)
        block_list = fw.find(self.name_internal_Address_Group, panos.objects.AddressGroup)
        ioc_list = block_list.about().get('static_value')
        if f"thehive-{ioc}" in ioc_list:
            ioc_list.remove(f"thehive-{ioc}")
            temp1 = panos.objects.AddressGroup(self.name_internal_Address_Group, static_value=ioc_list)
            fw.add(temp1)
            temp1.apply()
      
        panos.objects.AddressObject.refreshall(fw)
        if f"thehive-{ioc}" in str(fw.find(f"thehive-{ioc}", panos.objects.AddressObject)):
            try:
                deleted_ioc = fw.find(f"thehive-{ioc}", panos.objects.AddressObject)
                deleted_ioc.delete()
            except:
                self.report({'message': 'Responder did not comlite. Warning in AddressObject'})

        self.report({'message': 'Responder successfully deleted %s from %s' % (f"thehive-{ioc}",self.name_internal_Address_Group)})
        fw.commit()

if __name__ == '__main__':
    Unblock_ip().run()
