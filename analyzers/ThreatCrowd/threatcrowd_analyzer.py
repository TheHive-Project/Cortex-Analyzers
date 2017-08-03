#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import json
import requests
import re
import time
from multiprocessing import Pool

class ThreatCrowdAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.cortexURL = self.getParam('config.cortexURL', None, 'Cortex URL is missing')
        self.MISPSearch = self.getParam('config.MISPSearch', None, 'MISP Analyzer is missing')

    def runAnalyzer(self, analyzer, data, typ):
        try:
            r = requests.post(self.cortexURL+'/api/analyzer/'+analyzer+'/run', data='{"data": "'+data+'", "attributes": {"dataType": "'+typ+'", "tlp": 0}}', headers={'Content-type': 'application/json'})
            jobId = r.json()["id"]
            while True:
                res = requests.get(self.cortexURL+'/api/job/'+jobId).json()
                if res["status"] != "InProgress":
                    return res["report"]["full"]
                time.sleep(1)
        except Exception:
            return []

    def doMISPLookup(self, value, typ, last_resolved=None):
        result = {"value": value, "events": [], "status": None, "type": typ}
        if last_resolved:
            result['last_resolved'] = last_resolved
        try:
            ret = self.runAnalyzer(self.MISPSearch, value, typ)
            try:
                for mispInstance in ret["results"]:
                    for event in mispInstance["result"]:
                        # get url of event
                        event["url"] = mispInstance["url"]+"/events/view/"+event["id"]
                        result["events"].append(event)
                if len(result["events"]) > 0:
                    result["status"] = True
                else:
                    result["status"] = False
            except Exception:
                pass
        except Exception as e:
            pass
        return result
    
    def summary(self, raw):
        taxonomies = []
        value = ""
        level = "info"

        if raw.get("response_code") == "1":
            if self.data_type == "email":
                value = str(len(raw.get('domains')))+" domains"
            elif (self.data_type == "domain") or (self.data_type == "ip") or (self.data_type == "url"):
                if raw.get('votes') == 0:
                    value = "\"no Votes\""
                elif raw.get('votes') == 1:
                    level = "safe"
                    value = "\"not MALICIOUS\""
                elif raw.get('votes') == -1:
                    level = "malicious"
                    value = "\"MALICIOUS\""
            taxonomies.append(self.build_taxonomy(level, "ThreatCrowd", "Status", value))
        else:
            taxonomies.append(self.build_taxonomy(level, "ThreatCrowd", "Status", "\"no data\""))
        return {"taxonomies": taxonomies}   

    def run(self):
        # get input data
        Analyzer.run(self)
        data = self.getData()
        try:
            #data = self.getParam('data', None, 'Data is missing')
            if self.data_type == "email":
                r = requests.get("https://www.threatcrowd.org/searchApi/v2/email/report/", params = {"email": data})
            elif (self.data_type == "domain") or (self.data_type == "url"):
                r =  requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/", params = {"domain": data})
            elif self.data_type == "ip":
                r =  requests.get("https://www.threatcrowd.org/searchApi/v2/ip/report/", params = {"ip": data})
            elif self.data_type == "file":
                f = file(self.getParam('file', None, 'File is missing'))
                r = requests.get("https://www.threatcrowd.org/searchApi/v2/file/report/", params = {"report": f.md5()})
            else:
                self.unexpectedError('Unknown ThreatCrowd data type')

            rep = json.loads(r.content.decode())

            # do enrichment with misp search
            if rep.get('hashes'):
                rep['hashes'] = [self.doMISPLookup(h, "md5") for h in rep['hashes']]
            if rep.get('resolutions'):
                if (self.data_type == "domain") or (self.data_type == "url"):
                    rep['resolutions'] = [self.doMISPLookup(r['ip_address'], "ip", r['last_resolved']) for r in rep['resolutions']]
                elif self.data_type == "ip":
                    rep['resolutions'] = [self.doMISPLookup(r['domain'], "domain", r['last_resolved']) for r in rep['resolutions']]
            if rep.get('subdomains') :
                rep['subdomains'] = [self.doMISPLookup(s, "domain") for s in rep['subdomains']]
            if rep.get('domains'):
                rep['domains'] = [self.doMISPLookup(d, "domain") for d in rep['domains']]
            if rep.get('emails'):
                rep['emails'] = [self.doMISPLookup(e, "email") for e in rep['emails']]


            """
            # TODO fix errors
            pool = Pool()
            if rep.get('hashes'):
                resultsHashPool = [pool.apply_async(self.doMISPLookup, (a, "md5",)) for a in rep['hashes']]
            if rep.get('resolutions'):
                if (self.data_type == "domain") or (self.data_type == "url"):
                    resultsResolutionsPool = [pool.apply_async(self.doMISPLookup, (b['ip_address'], "ip",)) for b in rep['resolutions']]
                elif self.data_type == "ip":
                    resultsResolutionsPool = [pool.apply_async(self.doMISPLookup, (b['domain'], "domain",)) for b in rep['resolutions']]
            if rep.get('subdomains'):
                resultsSubdomainsPool = [pool.apply_async(self.doMISPLookup, (c, "domain",)) for c in rep['subdomains']]
            if rep.get('domains'):
                resultsDomainsPool = [pool.apply_async(self.doMISPLookup, (d, "domain",)) for d in rep['domains']]
            if rep.get('emails'):
                resultsEMailsPool = [pool.apply_async(self.doMISPLookup, (e, "email",)) for e in rep['emails']]

            pool.close()
            pool.join()

            if rep.get('hashes'):
                rep['hashes'] = [f.get() for f in resultsHashPool]
            if rep.get('resolutions'):
                rep['resolutions'] = [g.get() for g in resultsResolutionsPool]
            if rep.get('subdomains'):
                rep['subdomains'] = [h.get() for h in resultsSubdomainsPool]
            if rep.get('domains'):
                rep['domains'] = [i.get() for i in resultsDomainsPool]
            if rep.get('emails'):
                rep['emails'] = [k.get() for k in resultsEMailsPool]
            """

            # send result
            self.report(rep)

        except Exception as e:
            self.unexpectedError(e)

if __name__ == '__main__':
    ThreatCrowdAnalyzer().run()