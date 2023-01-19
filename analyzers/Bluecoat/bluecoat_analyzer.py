#!/usr/bin/env python
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import json
import requests
import re

class BluecoatAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam('config.service', 'search', 'Bluecoat service is missing, default method is used')

    def summary(self, raw):
        taxonomies = []
        if raw.get('categorization') and len(raw.get('categorization')) > 0:
            for cat in raw.get('categorization'):
                taxonomies.append(self.build_taxonomy("info", "Bluecoat", "Category", cat))
            return {"taxonomies": taxonomies}      

    def run(self):
        # get input data
        Analyzer.run(self)
        data = self.getParam('data', None, 'Data is missing')
        try:
            # send service
            if self.service == 'search':
                payload = {'url': data}
                r = requests.post('https://sitereview.bluecoat.com/rest/categorization', data=payload)
                rep = json.loads(r.content.decode())

                try:
                    rep["categorization"] = re.findall('<a[^>]*>([^<]*?)</a>', rep["categorization"])
                except:
                    pass
                try:
                    rep["ratedate"] = re.findall('Last Time Rated/Reviewed[^:]*: ([^<]*?)<img', rep["ratedate"])[0]
                except:
                    pass
                try:
                    del rep['locked_message']
                except:
                    pass

                # send result
                self.report(rep)
            else:
                self.error('Unknown Bluecoat service')

        except Exception as e:
            self.unexpectedError(e)

if __name__ == '__main__':
    BluecoatAnalyzer().run()