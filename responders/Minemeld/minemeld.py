#!/usr/bin/env python3
from cortexutils.responder import Responder
import requests
import json
import ipaddress

class Minemeld(Responder):
   def __init__(self):
       Responder.__init__(self)
       self.minemeld_url = self.get_param('config.minemeld_url', None, 'URL missing!')
       self.minemeld_user = self.get_param('config.minemeld_user', None, 'Username missing!')
       self.minemeld_password = self.get_param('config.minemeld_password', None, 'Password missing!')
       self.minemeld_indicator_list = self.get_param('config.minemeld_indicator_list', None, "List missing!")
       self.minemeld_share_level = self.get_param('config.minemeld_share_level', None, "Share level missing!")
       self.minemeld_confidence = self.get_param('config.minemeld_confidence', None, "Confidence level missing!")
       self.minemeld_ttl = self.get_param('config.minemeld_ttl', None, "TTL missing!")
       self.observable_type = self.get_param('data.dataType', None, "Data type is empty")
       self.observable_description = self.get_param('data.message', None, "Message is empty")
       self.observable = self.get_param('data.data', None, "Data is empty")
       
   
   def run(self):
       Responder.run(self)
       auth = (self.minemeld_user, self.minemeld_password)
       headers = {
            "Content-Type": "application/json"
       }
       
       # Check for indicator type
       if self.observable_type == "ip":
           try:
               ipaddress.IPv4Address(self.observable)
               indicator_type = "IPv4"
           except ValueError:
               try:
                   ipaddress.IPv6Address(self.observable)
                   indicator_type= "IPv6"
               except ValueError:
                   self.error({'message': "Not a valid IPv4/IPv6 address!"})
       elif self.observable_type == "url":
         indicator_type = "URL"
       elif self.observable_type == "domain":
         indicator_type = "Domain"
       
       # Check for comment
       if self.observable_description == "":
           comment = "Indicator submitted from TheHive"
       else:
           comment = self.observable_description
       
       # Build our payload
       payload = {
            "indicator": self.observable,
            "type": indicator_type,
            "comment": comment,
            "share_level": self.minemeld_share_level,
            "confidence": self.minemeld_confidence,
            "ttl": self.minemeld_ttl
       }

       # Send our request
       try:
           r = requests.post(str(self.minemeld_url) + '/config/data/' + str(self.minemeld_indicator_list) + '_indicators' + '/append?h=' + str(self.minemeld_indicator_list) + '&t=localdb',data=json.dumps(payload),headers=headers,auth=auth,verify=False)
           self.report({'message': "Indicator " + self.observable + " submitted to Minemeld."  })
       except:
           self.error({'message': r.text })
   
   def operations(self, raw):
      return [self.build_operation('AddTagToCase', tag='Minemeld:Indicator Added')] 

if __name__ == '__main__':
  Minemeld().run()
