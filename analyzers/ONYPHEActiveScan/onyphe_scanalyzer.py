#!/usr/bin/env python3

from cortexutils.analyzer import Analyzer
from scanyphe_api import Scanyphe,ScanypheError
import time
#from tld import get_fld # TODO FLD/subdomains check

class OnypheScanalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            "config.service", None, "Service parameter is missing"
        )
        self.onyphe_key = self.get_param("config.key", None, "Missing Onyphe API key")
        self.onyphe_client = None
        self.auto_import = self.get_param("config.auto_import", False) 
        self.onyphe_maxscantime = self.get_param("config.maxscantime", 120)
        self.onyphe_urlscan = self.get_param("config.urlscan", True)
        self.onyphe_vulnscan = self.get_param("config.vulnscan", True)
        self.onyphe_riskscan = self.get_param("config.riskscan", False)
        self.onyphe_asm = self.get_param("config.asm", False)
        self.onyphe_ports = self.get_param("config.ports", "")
        self.onyphe_import = self.get_param("config.import", False)
        self.onyphe_poll_interval = self.get_param("config.onyphe_poll_interval", 30)
        self.keep_all_tags = self.get_param("config.keep_all_tags", False)
        self.polling_interval = self.get_param("config.polling_interval", 60)
        self.base_url = self.get_param("config.base_url","https://www.onyphe.io") + self.get_param("config.base_uri","/api/v3/") #Trailing / is needed for urljoin 

    def summary(self, raw):
        taxonomies = []
        namespace = "ONYPHE"

        reportlist = []
        risklist = []
        cvelist = []
        
        for odoc in raw["results"]:
            if "forward" in odoc:
                assetport = str(odoc["ip"]) + ":" + str(odoc["port"]) + ":" + str(odoc["forward"])
            else:
                assetport = str(odoc["ip"]) + ":" + str(odoc["port"])

            if not assetport in reportlist:
                reportlist.append(assetport)
            if "cve" in odoc:
                for cve in odoc["cve"]:
                    cveipport = cve + ":" + str(odoc["ip"]) + ":" + str(odoc["port"])
                    if not cveipport in cvelist:
                        cvelist.append(cveipport)
            elif odoc["@category"] == "riskscan":
                risklist.append(assetport)
            
        if len(risklist) > 0:
            taxonomies.append(
                self.build_taxonomy(
                    "suspicious",
                    namespace,
                    "Risk",
                    "{} risks found".format(len(risklist)),
                )
            )
        if len(cvelist) > 0:
            taxonomies.append(
                self.build_taxonomy(
                    "malicious",
                    namespace,
                    "CVE",
                    "{} CVEs found".format(len(cvelist)),
                )
            )
        if len(reportlist) > 0:
            taxonomies.append(
                self.build_taxonomy(
                    "info",
                    namespace,
                    "Services",
                    "{} services found".format(len(reportlist)),
                )
            )
        else:
            taxonomies.append(
                self.build_taxonomy("info", namespace, "Services", "No services found",)
           )        
        
    
        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        build = {}
        data = self.get_param("data", None, "Data is missing")
        
        #ONYPHE scanalyzer artifact approach
        ## If data_type is ip, fqdn, we'd like to update existing observable but it seems importing tags not possible
        ## ... so currently if fqdn create ip observable, and vice-versa.
        ## If data_type is domain, create new observable for each IP/hostname
        ## for each observable data_type:data, consolidate all tags and return as artifacts
        
        try: 
            #parse ONYPHE documents
            for odoc in raw["results"]:
                #Define tags
                otags = []
                if odoc["@category"] == "riskscan":
                    otags.append("onyphe:risk")
                    for ta in odoc["tag"]:
                        if ta.split('::')[0] == 'risk':
                            otags.append(str(ta))
                
                if "cve" in odoc:
                    otags.append("onyphe:cve")
                    for cve in odoc["cve"]:
                        otags.append(str(cve))
                    for ta in odoc["tag"]:
                        otags.append(str(ta))

                if self.auto_import:
                    otags.append("autoImport:true")

                if self.keep_all_tags:
                    for ta in odoc["tag"]:
                        otags.append(str(ta))
                
                if "cpe" in odoc:
                    for cpe in odoc["cpe"]:
                        otags.append(str(cpe))
                    
                otags.append(str(odoc["protocol"]))
                otags.append(str(odoc["transport"]) + "/" + str(odoc["port"]))    
                
                if self.data_type == "ip":
                    if "forward" in odoc:
                        thisartifact = "fqdn:" + str(odoc["forward"])
                    elif "hostname" in odoc:
                        hostnamelist = odoc["hostname"]
                        #TODO: currently take first hostname. Possible take all of them, or ask user to configure this choice.
                        thisartifact = "fqdn:" + str(hostnamelist[0])        
                    elif "reverse" in odoc:
                        thisartifact = "fqdn:" + str(odoc["reverse"])
                    else: 
                        thisartifact = "ip:" + str(odoc["ip"])
                elif self.data_type == "fqdn":
                    thisartifact = "ip:" + str(odoc["ip"])
                elif self.data_type == "domain":
                    if "forward" in odoc:
                        thisartifact = "fqdn:" + str(odoc["forward"])
                    elif "hostname" in odoc:
                        hostnamelist = odoc["hostname"]
                        #TODO: currently take first hostname. Possible take all of them, or ask user to configure this choice.
                        thisartifact = "fqdn:" + str(hostnamelist[0])        
                    elif "reverse" in odoc:
                        thisartifact = "fqdn:" + str(odoc["reverse"])
                    else: 
                        thisartifact = "ip:" + str(odoc["ip"])
                    
                if thisartifact in build:
                    existing_tags = build[thisartifact]
                    for tag in existing_tags:
                        if not tag in otags:
                            otags.append(tag)
                    
                build[thisartifact] = otags  
        
        except Exception as e:
            self.unexpectedError(e)
            
        for key in build:
            type = key.split(':')[0]
            data = key.split(':')[1]
            artifacts.append(self.build_artifact(type, data, tags=otags))
                
        return artifacts


    def run(self):
        Analyzer.run(self)
        
        self.onyphe_client = Scanyphe(self.onyphe_key, self.base_url)
        data = self.get_param("data", None, "Data is missing")
        try:
            #try and launch a scan
            
            #identify data type
            if self.data_type == "ip":
                path = "ondemand/scope/ip/single"
                scan_params = {'ip': data}
            elif self.data_type == "domain":
                path = "ondemand/scope/domain/single"
                scan_params = {'domain': data}
            elif self.data_type == "fqdn":
                path = "ondemand/scope/hostname/single"
                scan_params = {'hostname': data}
            
            #build params dictionary
            scan_params['maxscantime'] = self.onyphe_maxscantime
            scan_params['ports'] = self.onyphe_ports
            if self.onyphe_urlscan == True:
                scan_params['urlscan'] = 'true'
            else:
                scan_params['urlscan'] = 'false'
            if self.onyphe_vulnscan == True:
                scan_params['vulnscan'] = 'true'
            else:
                scan_params['vulnscan'] = 'false'
            if self.onyphe_riskscan == True:
                scan_params['riskscan'] = 'true'
            else:
                scan_params['riskscan'] = 'false'
            if self.onyphe_asm == True:
                scan_params['asm'] = 'true'
            else:
                scan_params['asm'] = 'false'
            if self.onyphe_import == True:
                scan_params['import'] = 'true'
            else:
                scan_params['import'] = 'false'
            
            #call appropriate scan API
            scanid_result = self.onyphe_client.scan(path, scan_params)
            
            #handle errors else get scan_id
            if 'error' in scanid_result.keys():
                if scanid_result['error'] > 0:
                    error_text = "Scan launch failed. Error code " + str(scanid_result['Error']) + " : " + scanid_result['text']
                    raise ScanypheError(error_text)
                else:
                    scanid = scanid_result['scan_id']
            else:
                error_text = "Scan launch failed. API said : {say}".format(say=str(scanid_result))
                raise ScanypheError(error_text)
        except Exception as e:
            self.unexpectedError(e)


        try:
            #now wait onyphe poll time before polling results API
            scan_finished = False
            intervals = (self.onyphe_maxscantime // self.onyphe_poll_interval) + 1
            interval = self.onyphe_poll_interval
            
            for x in range(intervals):
                time.sleep(interval)
                waited = (x+1) * interval
                results = self.onyphe_client.results(scanid)
                
                if results['error'] == 0:
                    scan_finished = True
                    break
                elif results['error'] != 2027:
                    error_text = "Scan results fetch failed after " + str(waited) + " secs. Error code " + str(results['error']) + " : " + results['text']
                    raise ScanypheError(error_text)
            
            if scan_finished == False:
                    raise ScanypheError("Scan failed : no results were received from Scanyphe after {say} secs".format(say=str(waited)))
            
            results["total_docs"] = len(results["results"])
            
            self.report(results)
        
        except Exception as e:
            self.unexpectedError(e)
        

if __name__ == "__main__":
    OnypheScanalyzer().run()
    
