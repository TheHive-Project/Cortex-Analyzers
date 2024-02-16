#!/usr/bin/env python3

from cortexutils.analyzer import Analyzer
from onyphe_api import Onyphe
from datetime import datetime
#from tld import get_fld # TODO FLD/subdomains check

class OnypheAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            "config.service", None, "Service parameter is missing"
        )
        self.onyphe_key = self.get_param("config.key", None, "Missing Onyphe API key")
        self.onyphe_client = None
        self.onyphe_category = self.get_param("config.category", "datascan") #only used for Search service
        self.time_filter = self.get_param("config.time_filter", "-since:1M") 
        self.auto_import = self.get_param("config.auto_import", False) 
        self.verbose_taxonomies = self.get_param("config.verbose_taxonomies", False) #Only used for Summary service
        self.polling_interval = self.get_param("config.polling_interval", 60)

    def summary(self, raw):
        taxonomies = []
        namespace = "ONYPHE"

        if (self.service == "search" and self.onyphe_category == "vulnscan") or self.service == "vulnscan":
            #report number of CVEs
            
            reportlist = []
            
            for odoc in raw["results"]:
                if "cve" in odoc:
                    for cve in odoc["cve"]:
                        if cve not in reportlist:
                            reportlist.append(cve)

            if len(reportlist) > 0:
                taxonomies.append(
                    self.build_taxonomy(
                        "malicious",
                        namespace,
                        "CVE",
                        "{} CVE found".format(len(reportlist)),
                    )
                )
            else:
                taxonomies.append(
                    self.build_taxonomy("info", namespace, "CVE", "No CVE found",)
                )
                
        elif self.service == "search" and self.onyphe_category == "riskscan":
            #report number of unique risks/ports/services
            
            reportlist = []
                        
            for odoc in raw["results"]:
                if "forward" in odoc:
                    assetport = str(odoc["ip"]) + ":" + str(odoc["port"]) + ":" + str(odoc["forward"])
                else:
                    assetport = str(odoc["ip"]) + ":" + str(odoc["port"])
                if not assetport in reportlist:
                    reportlist.append(assetport)

            if len(reportlist) > 0:
                taxonomies.append(
                    self.build_taxonomy(
                        "suspicious",
                        namespace,
                        "Risk",
                        "{} risks found".format(len(reportlist)),
                    )
                )
            else:
                taxonomies.append(
                    self.build_taxonomy("info", namespace, "Risk", "No risks found",)
                )
                
        elif self.service == "search" and self.onyphe_category == "datascan":
            #report number of unique ports/services
            
            reportlist = []
                        
            for odoc in raw["results"]:
                if "forward" in odoc:
                    assetport = str(odoc["ip"]) + ":" + str(odoc["port"]) + ":" + str(odoc["forward"])
                else:
                    assetport = str(odoc["ip"]) + ":" + str(odoc["port"])
                if not assetport in reportlist:
                    reportlist.append(assetport)

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
        
        elif self.service == "asm":
            #report number of unique risks/ports/services
            
            reportlist = []
                        
            for odoc in raw["results"]:
                if "forward" in odoc:
                    assetport = str(odoc["ip"]) + ":" + str(odoc["port"]) + ":" + str(odoc["forward"])
                else:
                    assetport = str(odoc["ip"]) + ":" + str(odoc["port"])
                if not assetport in reportlist:
                    reportlist.append(assetport)

            if len(reportlist) > 0:
                taxonomies.append(
                    self.build_taxonomy(
                        "suspicious",
                        namespace,
                        "Risk",
                        "{} risks found".format(len(reportlist)),
                    )
                )
            else:
                taxonomies.append(
                    self.build_taxonomy("info", namespace, "Risk", "No risks found",)
                )
        
        elif (self.service == "summary" and not self.verbose_taxonomies) or self.service == "threatlist":

            threatlist = list(
                set(
                    [
                        r["threatlist"]
                        for r in raw["results"]
                        if r["@category"] == "threatlist"
                    ]
                )
            )

            if len(threatlist) > 0:
                taxonomies.append(
                    self.build_taxonomy(
                        "malicious",
                        namespace,
                        "Threat",
                        "{} threat found".format(len(threatlist)),
                    )
                )
            else:
                taxonomies.append(
                    self.build_taxonomy("info", namespace, "Threat", "No threat found",)
                )
                
        elif self.service == "summary" and self.verbose_taxonomies:

            output_data = {
                "threatlist": {},
                "subnet": {},
                "port": {},
                "reverse": {},
                "forward": {},
                "resolver": {},
            }

            for r in raw["results"]:

                if r["@category"] == "threatlist":
                    threatlist = r["threatlist"]
                    if threatlist not in output_data["threatlist"]:
                        output_data["threatlist"][threatlist] = {
                            "dates": [],
                            "subnets": [],
                            "count": 0,
                        }
                    if (
                        r["seen_date"]
                        not in output_data["threatlist"][threatlist]["dates"]
                    ):
                        output_data["threatlist"][threatlist]["dates"].append(
                            r["seen_date"]
                        )
                        output_data["threatlist"][threatlist]["count"] += 1
                    if (
                        r["subnet"]
                        not in output_data["threatlist"][threatlist]["subnets"]
                    ):
                        output_data["threatlist"][threatlist]["subnets"].append(
                            r["subnet"]
                        )

                elif r["@category"] == "geoloc":
                    taxonomies.append(
                        self.build_taxonomy(
                            "info",
                            namespace,
                            "Geolocate",
                            "country: {}, {}".format(
                                r["country"],
                                "location: {}".format(r["location"])
                                if not r.get("city", None)
                                else "city: {}".format(r["city"]),
                            ),
                        )
                    )

                elif r["@category"] == "inetnum":
                    subnet = r["subnet"]
                    if subnet not in output_data["subnet"]:
                        output_data["subnet"][subnet] = {"dates": []}
                    if r["seen_date"] not in output_data["subnet"][subnet]["dates"]:
                        output_data["subnet"][subnet]["dates"].append(r["seen_date"])

                elif r["@category"] in ["ports", "datascan"]:
                    port = r["port"]
                    if port not in output_data["port"]:
                        output_data["port"][port] = {"dates": []}
                    if r["seen_date"] not in output_data["port"][port]["dates"]:
                        output_data["port"][port]["dates"].append(r["seen_date"])

                elif r["@category"] == "reverse":
                    reverse = r["domain"]
                    if reverse not in output_data["reverse"]:
                        output_data["reverse"][reverse] = {"dates": []}
                    if r["seen_date"] not in output_data["reverse"][reverse]["dates"]:
                        output_data["reverse"][reverse]["dates"].append(r["seen_date"])

                elif r["@category"] == "forward":
                    forward = r["domain"]
                    if forward not in output_data["forward"]:
                        output_data["forward"][forward] = {"dates": []}
                    if r["seen_date"] not in output_data["forward"][forward]["dates"]:
                        output_data["forward"][forward]["dates"].append(r["seen_date"])

                elif r["@category"] == "resolver":
                    resolver = r["hostname"]
                    if resolver not in output_data["resolver"]:
                        output_data["resolver"][resolver] = {"dates": []}
                    if r["seen_date"] not in output_data["resolver"][resolver]["dates"]:
                        output_data["resolver"][resolver]["dates"].append(
                            r["seen_date"]
                        )

            for threatlist, threat_data in output_data["threatlist"].items():
                taxonomies.append(
                    self.build_taxonomy(
                        "malicious",
                        namespace,
                        "Threat",
                        "threatlist: {}, event count: {}".format(
                            threatlist, threat_data["count"]
                        ),
                    )
                )

            for topic in ["subnet", "port", "forward", "reverse", "resolver"]:
                for item, item_data in output_data[topic].items():
                    taxonomies.append(
                        self.build_taxonomy(
                            "info",
                            namespace,
                            item.capitalize(),
                            "{} {} last seen {}".format(
                                topic,
                                item,
                                max(
                                    datetime.strptime(x, "%Y-%m-%d")
                                    for x in item_data["dates"]
                                ),
                            ),
                        )
                    )

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        dedup = {}
        
        if self.service != "summary":
            for odoc in raw["results"]:
                if ("forward" in odoc and "port" in odoc):
                    dedup_key = str(odoc["ip"]) + ":" + str(odoc["port"]) + ":" + str(odoc["forward"])
                elif "port" in odoc:
                    dedup_key = str(odoc["ip"]) + ":" + str(odoc["port"])
                elif "threatlist" in odoc:
                    dedup_key = str(odoc["ip"]) + ":" + str(odoc["threatlist"])  #dedup key for threatlist, as no port in that category                  
                else:
                    dedup_key = str(odoc["ip"])
                
                newasset = True
                if dedup_key in dedup:
                    newdate = datetime.strptime(odoc["seen_date"], "%Y-%m-%d")
                    olddate = datetime.strptime(dedup[dedup_key], "%Y-%m-%d")
                    if olddate > newdate:
                        newasset = False
                
                if newasset:
                    if odoc["@category"] == "riskscan": #category riskscan, so artifacts are risks
                        otags=["onyphe:risk"]
                        if self.auto_import:
                            otags.append("autoImport:true")
                        for ta in odoc["tag"]:
                            otags.append(str(ta))
                        if "cve" in odoc:
                            for cve in odoc["cve"]:
                                otags.append(str(cve))
                        otags.append(str(odoc["protocol"]))
                        otags.append(str(odoc["transport"]) + "/" + str(odoc["port"]))    
                        if self.data_type == "ip": #datatype is IP, so create fqdn artifacts
                            if "hostname" in odoc:
                                for fqdns in odoc["hostname"]:
                                    artifacts.append(
                                        self.build_artifact(
                                            "fqdn", str(fqdns), tags=otags
                                            )
                                        )            
                            elif "reverse" in odoc: #no hostnames so use reverse if possible
                                artifacts.append(
                                    self.build_artifact(
                                        "fqdn", odoc["reverse"], tags=otags
                                        )
                                    )                       
                            else: #no hostnames or reverse so use ip, but user can't import as observable exists :(
                                artifacts.append(
                                    self.build_artifact(
                                        "ip", str(odoc["ip"]), tags=otags
                                        )
                                    )
                        else:
                            artifacts.append(
                                self.build_artifact(
                                    "ip", str(odoc["ip"]), tags=otags
                                    )
                                )
                    elif odoc["@category"] == "vulnscan": #category vulnscan, so artifacts are cves
                        if "cve" in odoc:
                            otags=["onyphe:cve"]
                            if self.auto_import:
                                otags.append("autoImport:true")
                            for cve in odoc["cve"]:
                                otags.append(str(cve))
                            if "tag" in odoc:
                                for ta in odoc["tag"]:
                                    otags.append(str(ta))   
                            otags.append(str(odoc["protocol"]))
                            otags.append(str(odoc["transport"]) + "/" + str(odoc["port"]))    
                            if self.data_type == "ip": #datatype is IP, so create fqdn artifacts
                                if "hostname" in odoc:
                                    for fqdns in odoc["hostname"]:
                                        artifacts.append(
                                            self.build_artifact(
                                                "fqdn", str(fqdns), tags=otags
                                                )
                                            )            
                                elif "reverse" in odoc: #no hostnames so use reverse if possible
                                    artifacts.append(
                                        self.build_artifact(
                                            "fqdn", odoc["reverse"], tags=otags
                                            )
                                        )                       
                                else: #no hostnames or reverse so use ip, but user can't import as observable exists :(
                                    artifacts.append(
                                        self.build_artifact(
                                            "ip", str(odoc["ip"]), tags=otags
                                            )
                                        )
                            else:
                                artifacts.append(
                                    self.build_artifact(
                                        "ip", str(odoc["ip"]), tags=otags
                                        )
                                    )
                    elif odoc["@category"] == "datascan" or odoc["@category"] == "onionscan": #category datascan, so artifacts is all results
                        otags=["onyphe:asset"]
                        if self.auto_import:
                            otags.append("autoImport:true")
                        otags.append(str(odoc["protocol"]))
                        otags.append(str(odoc["transport"]) + "/" + str(odoc["port"]))
                        if "tag" in odoc:
                            for ta in odoc["tag"]:
                                otags.append(str(ta))   
                        if self.data_type == "ip": #datatype is IP, so create fqdn artifacts
                            if "hostname" in odoc:
                                for fqdns in odoc["hostname"]:
                                    artifacts.append(
                                        self.build_artifact(
                                            "fqdn", str(fqdns), tags=otags
                                            )
                                        )            
                            elif "reverse" in odoc: #no hostnames so use reverse if possible
                                artifacts.append(
                                    self.build_artifact(
                                        "fqdn", odoc["reverse"], tags=otags
                                        )
                                    )                       
                            else: #no hostnames or reverse so use ip, but user can't import as observable exists :(
                                artifacts.append(
                                    self.build_artifact(
                                        "ip", str(odoc["ip"]), tags=otags
                                        )
                                    )
                        else:
                            artifacts.append(
                                self.build_artifact(
                                    "ip", str(odoc["ip"]), tags=otags
                                    )
                                )
                    elif odoc["@category"] == "threatlist":
                        otags=["onyphe:threat"]
                        if self.auto_import:
                            otags.append("autoImport:true")
                        if "tag" in odoc:
                            for ta in odoc["tag"]:
                                otags.append(str(ta))   
                        if self.data_type == "ip": #datatype is IP, so create fqdn artifacts
                            if "hostname" in odoc:
                                for fqdns in odoc["hostname"]:
                                    artifacts.append(
                                        self.build_artifact(
                                            "fqdn", str(fqdns), tags=otags
                                            )
                                        )            
                            elif "reverse" in odoc: #no hostnames so use reverse if possible
                                artifacts.append(
                                    self.build_artifact(
                                        "fqdn", odoc["reverse"], tags=otags
                                        )
                                    )                       
                            else: #no hostnames or reverse so use ip, but user can't import as observable exists :(
                                artifacts.append(
                                    self.build_artifact(
                                        "ip", str(odoc["ip"]), tags=otags
                                        )
                                    )
                        else:
                            artifacts.append(
                                self.build_artifact(
                                    "ip", str(odoc["ip"]), tags=otags
                                    )
                                )   
                    else: #category other, so assuming resolver / hostname enumeration
                        otags=["onyphe:" + self.onyphe_category]
                        if self.auto_import: #YOLO
                            otags.append("autoImport:true")
                        if "tag" in odoc:
                            for ta in odoc["tag"]:
                                otags.append(str(ta))   
                        if self.data_type == "ip": #datatype is IP, so create fqdn artifacts
                            if "hostname" in odoc:
                                for fqdns in odoc["hostname"]:
                                    artifacts.append(
                                        self.build_artifact(
                                            "fqdn", str(fqdns), tags=otags
                                            )
                                        )            
                            elif "reverse" in odoc: #no hostnames so use reverse if possible
                                artifacts.append(
                                    self.build_artifact(
                                        "fqdn", odoc["reverse"], tags=otags
                                        )
                                    )                       
                            else: #no hostnames or reverse so use ip, but user can't import as observable exists :(
                                artifacts.append(
                                    self.build_artifact(
                                        "ip", str(odoc["ip"]), tags=otags
                                        )
                                    )
                        else:
                            artifacts.append(
                                self.build_artifact(
                                    "ip", str(odoc["ip"]), tags=otags
                                    )
                                )
                    dedup[dedup_key] = str(odoc["seen_date"])
        return artifacts

    def run(self):
        Analyzer.run(self)
        try:
            self.onyphe_client = Onyphe(self.onyphe_key)
            data = self.get_param("data", None, "Data is missing")
            
            if self.service == "search":
                results = self.onyphe_client.search(data, self.data_type,self.onyphe_category,self.time_filter)
                results["category"] = self.onyphe_category
                results["total_category"] = len(results["results"])
            
            elif self.service == "asm":
                self.onyphe_category = "riskscan" #ASM service so force category to riskscan
                self.fields_filter = self.get_param("config.fields_filter", "ip,port,protocol,tag,tls,cpe,cve,hostname,domain,alternativeip,forward,url,organization,transport,organization,device.class,device.product,device.productvendor,device.productversion,product,productvendor,productversion") 
                asmfilter = self.time_filter + "+-fields:" + self.fields_filter #Fields filter is faster and saves space in The Hive database.
                results = self.onyphe_client.search(data, self.data_type,self.onyphe_category,asmfilter.replace(",","%2C"))
                #results = self.onyphe_client.search(data, self.data_type,self.onyphe_category,self.time_filter)
                results["category"] = self.onyphe_category
                results["total_category"] = len(results["results"])
            
            elif self.service == "vulnscan":
                self.onyphe_category = "vulnscan" 
                
                vulnfilter = self.time_filter
                if self.get_param("config.only_vulnerable", True):
                    vulnfilter += "+-exists:cve"
                results = self.onyphe_client.search(data, self.data_type,self.onyphe_category,vulnfilter)
                results["category"] = self.onyphe_category
                results["total_category"] = len(results["results"])
            
            elif self.service == "threatlist":
                self.onyphe_category = "threatlist" 
                
                results = self.onyphe_client.search(data, self.data_type,self.onyphe_category,self.time_filter)
                results["category"] = self.onyphe_category
                results["total_category"] = len(results["results"])
                        
            elif self.service == "summary":
                results = self.onyphe_client.summary(data, self.data_type)
                results["totals_category"] = {
                    k: len(
                        [x for x in results["results"] if x["@category"] == k]
                    )
                    for k in [
                        "threatlist",
                        "threats",
                        "geoloc",
                        "inetnum",
                        "ports",
                        "reverse",
                        "datascan",
                        "forward",
                    ]
                }

            self.report(results)

        except Exception:
            pass


if __name__ == "__main__":
    OnypheAnalyzer().run()
