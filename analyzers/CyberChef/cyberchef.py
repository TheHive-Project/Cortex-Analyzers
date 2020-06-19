#!/usr/bin/env python3
# encoding: utf-8

import json
import requests
from cortexutils.analyzer import Analyzer

class CyberchefAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.observable = self.get_param('data', None, 'Data missing!')
        self.service = self.get_param('config.service', None, 'Service is missing')
        self.url = self.get_param('config.url', None, 'URL is missing')

    def summary(self, raw):
        taxonomies = []
        level = 'info'
        namespace = 'CyberChef'
 
        # Set predicate for output_data
        predicate = self.service
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, "baked!"))
 
        return {"taxonomies": taxonomies}
   
    def run(self):
        try:
            observable = str(self.observable)
            url = self.url
            if self.service == 'FromHex':
                data = {"input": observable, "recipe":{"op":"From Hex", "args": ["Auto"]}} 
            elif self.service == "FromBase64":
                data = { "input": observable, "recipe":[{"op":"From Base64","args":["A-Za-z0-9+/=",True]}]}
            elif self.service == "FromCharCode":
                # Recipe from https://github.com/mattnotmax/cyberchef-recipes#recipe-3---from-charcode
                data = { "input": observable, "recipe":[{"op":"Regular expression","args":["User defined","([0-9]{2,3}(,\\s|))+",True,True,False,False,False,False,"List matches"]},{"op":"From Charcode","args":["Comma",10]},{"op":"Regular expression","args":["User defined","([0-9]{2,3}(,\\s|))+",True,True,False,False,False,False,"List matches"]},{"op":"From Charcode","args":["Space",10]}]}
            headers = { 'Content-Type': 'application/json' }
            r = requests.post(url.strip('/') + '/bake', headers=headers, data=json.dumps(data))
            if r.status_code == 200:
                output_data = "".join([chr(x) for x in r.json().get('value', [])])
                self.report({ 'input_data': observable, 'output_data': output_data })
            else:
                self.error('Server responded with %d: %s' % (r.status_code, r.text))
        except:
            self.error("Could not convert provided data.")

if __name__ == '__main__':
    CyberchefAnalyzer().run()
    
