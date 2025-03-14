#!/usr/bin/env python3

from cortexutils.analyzer import Analyzer
from onyphe_api import Onyphe,OtherError
from datetime import datetime
from dateutil import parser
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
        self.base_url = self.get_param("config.base_url","https://www.onyphe.io") + self.get_param("config.base_uri","/api/v2/") #Trailing / is needed for urljoin
        self.return_other_artifacts = self.get_param("config.return_other_artifacts", False)
        self.keep_all_tags = self.get_param("config.keep_all_tags", False)

    def summary(self, raw):
        taxonomies = []
        namespace = "ONYPHE"

        if self.service != "summary":
            reportlist = []
            risklist = []
            cvelist = []
            
            for odoc in raw["results"]:
                if odoc["@category"] == "ctiscan" and "http" in odoc and "vhost" in odoc["http"]:
                    dedupkey = str(odoc["ip"]["dest"]) + ":" + str(odoc["tcp"]["dest"]) + ":" + str(odoc["http"]["vhost"])
                elif odoc["@category"] == "ctiscan" and odoc["app"]["transport"] == "tcp":
                    dedupkey = str(odoc["ip"]["dest"]) + ":" + str(odoc["tcp"]["dest"])
                elif odoc["@category"] == "ctiscan" and odoc["app"]["transport"] == "udp":
                    dedupkey = str(odoc["ip"]["dest"]) + ":" + str(odoc["udp"]["dest"])
                elif "forward" in odoc:
                    dedupkey = str(odoc["ip"]) + ":" + str(odoc["port"]) + ":" + str(odoc["forward"])
                else:
                    dedupkey = str(odoc["ip"]) + ":" + str(odoc["port"])

                if not dedupkey in reportlist:
                    reportlist.append(dedupkey)
                if "cve" in odoc:
                    for cve in odoc["cve"]:
                        cveipport = cve + ":" + str(odoc["ip"]) + ":" + str(odoc["port"])
                        if not cveipport in cvelist:
                            cvelist.append(cveipport)
                elif odoc["@category"] == "riskscan":
                    risklist.append(dedupkey)
                elif odoc["@category"] == "ctiscan" and "tag" in odoc:
                    for tag in odoc["tag"]:
                        if tag == "risk":
                            risklist.append(dedupkey)
                            break
 
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
                        "{} unique services (ip:port:vhost) found".format(len(reportlist)),
                    )
                )
 
            if (len(reportlist) == 0 and len(risklist) == 0 and len(cvelist) == 0):
                taxonomies.append(
                    self.build_taxonomy("info", namespace, "Services", "No services found",)
            )

        elif (self.service == "summary" and not self.verbose_taxonomies):

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
        build = {}
        data = self.get_param("data", None, "Data is missing")

        if self.service != "summary":
            try: 
                for odoc in raw["results"]:
                    if odoc["@category"] == "ctiscan" and "http" in odoc and "vhost" in odoc["http"]:
                        dedupkey = str(odoc["ip"]["dest"]) + ":" + str(odoc["tcp"]["dest"]) + ":" + str(odoc["http"]["vhost"])
                    elif odoc["@category"] == "ctiscan" and "tcp" in odoc:
                        dedupkey = str(odoc["ip"]["dest"]) + ":" + str(odoc["tcp"]["dest"])
                    elif odoc["@category"] == "ctiscan" and "udp" in odoc:
                        dedupkey = str(odoc["ip"]["dest"]) + ":" + str(odoc["udp"]["dest"])
                    elif "forward" in odoc and "port" in odoc:
                        dedupkey = str(odoc["ip"]) + ":" + str(odoc["port"]) + ":" + str(odoc["forward"])
                    elif "threatlist" in odoc:
                        dedupkey = str(odoc["ip"]) + ":" + str(odoc["threatlist"])
                    else:
                        dedupkey = str(odoc["ip"]) + ":" + str(odoc["port"])
    
                    newasset = True
                    if dedupkey in dedup:
                        newdate = parser.parse(odoc["@timestamp"])
                        olddate = parser.parse(dedup[dedupkey])
                        if olddate > newdate:
                            newasset = False
    
                    if newasset:
                        thisartifact = ""
                        #parse ONYPHE documents. Manage both legacy and ctiscan data models here.
                        otags = []
                        if odoc["@category"] == "riskscan" or (odoc["@category"] == "ctiscan" and "tag" in odoc):
                            for ta in odoc["tag"]:
                                if ta.split('::')[0] == 'risk':
                                    otags.append(str(ta))
                                    otags.append("onyphe:risk")
                        
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
                        elif "component" in odoc:
                            for cpe in odoc["component"]["cpe"]:
                                otags.append(str(cpe))

                        if "protocol" in odoc:                                
                            otags.append(str(odoc["protocol"]))
                        elif "app" in odoc and "protocol" in odoc["app"]:                                
                            otags.append(str(odoc["app"]["protocol"]))
                        
                        if "transport" in odoc and "port" in odoc:                                
                            otags.append(str(odoc["transport"]) + "/" + str(odoc["port"]))
                        elif "tcp" in odoc:                                
                            otags.append("tcp/" + str(odoc["tcp"]["dest"]))
                        elif "udp" in odoc:                                
                            otags.append("udp/" + str(odoc["udp"]["dest"]))
                        
                        if self.return_other_artifacts:
                            thisartifact = "other#"
                            if odoc["@category"] == "ctiscan":
                                #TODO handle vhost in other parsing in run()
                                #if "http" in odoc and "vhost" in odoc["http"]:
                                #    thisartifact += str(odoc["http"]["vhost"])
                                #else:
                                thisartifact += str(odoc["ip"]["dest"])
                                if "tcp" in odoc:                                
                                    thisartifact += ":" + str(odoc["tcp"]["dest"])
                                elif "udp" in odoc:                                
                                    thisartifact += ":" + str(odoc["udp"]["dest"])
                        elif self.data_type == "fqdn":
                            #the approach here is to try and return pivots. IPs for hostnames, and hostnames for IPs.
                            if "dest" in odoc["ip"]:
                                thisartifact = "ip#" + str(odoc["ip"]["dest"])
                            else: 
                                thisartifact = "ip#" + str(odoc["ip"])
                        elif self.data_type == "ip":
                            if "forward" in odoc:
                                thisartifact = "fqdn#" + str(odoc["forward"])
                            elif "http" in odoc and "vhost" in odoc["http"]:
                                thisartifact = "fqdn#" + str(odoc["http"]["vhost"])
                            elif "hostname" in odoc:
                                hostnamelist = odoc["hostname"]
                                #TODO: currently take first hostname. Possible take all of them, or ask user to configure this choice.
                                thisartifact = "fqdn#" + str(hostnamelist[0])
                            elif "dns" in odoc and "hostname" in odoc["dns"]:
                                thisartifact = "fqdn#" + str(odoc["dns"]["hostname"][0])
                            elif "cert" in odoc and "hostname" in odoc["dns"]:
                                thisartifact = "fqdn#" + str(odoc["cert"]["hostname"][0])
                        else:
                            if "forward" in odoc:
                                thisartifact = "fqdn#" + str(odoc["forward"])
                            elif "http" in odoc and "vhost" in odoc["http"]:
                                thisartifact = "fqdn#" + str(odoc["http"]["vhost"])
                            elif "hostname" in odoc:
                                hostnamelist = odoc["hostname"]
                                #TODO: currently take first hostname. Possible take all of them, or ask user to configure this choice.
                                thisartifact = "fqdn#" + str(hostnamelist[0])
                            elif "dns" in odoc and "hostname" in odoc["dns"]:
                                thisartifact = "fqdn#" + str(odoc["dns"]["hostname"][0])
                            elif "cert" in odoc and "hostname" in odoc["dns"]:
                                thisartifact = "fqdn#" + str(odoc["cert"]["hostname"][0])
                            elif "dest" in odoc["ip"]:
                                thisartifact = "ip#" + str(odoc["ip"]["dest"])
                            else: 
                                thisartifact = "ip#" + str(odoc["ip"])
                        
                        if thisartifact in build:
                            existing_tags = build[thisartifact]
                            for tag in existing_tags:
                                if not tag in otags:
                                    otags.append(tag)
                            
                        build[thisartifact] = otags  
                        dedup[dedupkey] = odoc["@timestamp"]

            except Exception as e:
                self.unexpectedError("Error: " + e + " in artifacts")
                  
        for key in build:
            type = key.split('#')[0]
            data = key.split('#')[1]
            artifacts.append(self.build_artifact(type, data, tags=build[key]))
                
        return artifacts
    
    def operations(self, raw):
        operations = []
        otags = []
        data = self.get_param("data", None, "Data is missing")
        
        if self.service != "summary":
            try: 
                for odoc in raw["results"]:
                    matchdata = False
                    #does odoc match data observable.
                    if self.data_type == "fqdn":
                        if "forward" in odoc and odoc["forward"] == data:
                            matchdata = True
                        elif "http" in odoc and "vhost" in odoc["http"] and odoc["http"]["vhost"] == data:
                            matchdata = True
                        elif "dns" in odoc and "hostname" in odoc["dns"] and data in odoc["dns"]["hostname"]:
                            matchdata = True
                        elif "cert" in odoc and "hostname" in odoc["cert"] and data in odoc["cert"]["hostname"]:
                            matchdata = True
                        elif "hostname" in odoc and data in odoc["hostname"]:
                            matchdata = True
                    elif self.data_type == "ip":
                        if "dest" in odoc["ip"] and odoc["ip"]["dest"] == data:
                            matchdata = True
                        elif odoc["ip"] == data:
                            matchdata = True
                    elif self.data_type == "other":
                            matchdata = True
                    
                    if matchdata:                        
                        #parse ONYPHE documents. Manage both legacy and ctiscan data models here.
                        if odoc["@category"] == "riskscan" or (odoc["@category"] == "ctiscan" and "tag" in odoc):
                            for ta in odoc["tag"]:
                                if ta.split('::')[0] == 'risk':
                                    otags.append(str(ta))
                                    otags.append("onyphe:risk")
                        
                        if "cve" in odoc:
                            otags.append("onyphe:cve")
                            for cve in odoc["cve"]:
                                otags.append(str(cve))
                            for ta in odoc["tag"]:
                                otags.append(str(ta))

                        if self.keep_all_tags:
                            for ta in odoc["tag"]:
                                otags.append(str(ta))
                        
                        if "cpe" in odoc:
                            for cpe in odoc["cpe"]:
                                otags.append(str(cpe))
                        elif "component" in odoc:
                            for cpe in odoc["component"]["cpe"]:
                                otags.append(str(cpe))

                        if "protocol" in odoc:                                
                            otags.append(str(odoc["protocol"]))
                        elif "app" in odoc and "protocol" in odoc["app"]:                                
                            otags.append(str(odoc["app"]["protocol"]))
                        
                        if "transport" in odoc and "port" in odoc:                                
                            otags.append(str(odoc["transport"]) + "/" + str(odoc["port"]))
                        elif "tcp" in odoc:                                
                            otags.append("tcp/" + str(odoc["tcp"]["dest"]))
                        elif "udp" in odoc:                                
                            otags.append("udp/" + str(odoc["udp"]["dest"]))
               
            except Exception as e:
                self.unexpectedError("Error: " + e + " in operations")
       
        for this_tag in otags:
            operations.append(self.build_operation('AddTagToArtifact', tag=this_tag))
       
        return operations

    def run(self):
        Analyzer.run(self)
        try:
            self.onyphe_client = Onyphe(self.onyphe_key, self.base_url)
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

            elif self.service == "ctiscan":
                self.onyphe_category = "ctiscan" 
                ctifilter = ''
                #case data_type
                if self.data_type == "ip":
                    ctifilter += 'ip.dest:{ip} '.format(ip=data)
                elif self.data_type == "fqdn":
                    ctifilter += '?dns.hostname:{hostname} ?cert.hostname:{hostname} '.format(hostname=data)
                elif self.data_type == "domain":
                    ctifilter += '?dns.domain:{domain} ?cert.domain:{domain} '.format(domain=data)
                elif self.data_type == "hash":
                    ctifilter += '?cert.fingerprint.md5:{data} '.format(data=data)
                    ctifilter += '?cert.fingerprint.sha1:{data} '.format(data=data)
                    ctifilter += '?cert.fingerprint.sha256:{data} '.format(data=data)
                    ctifilter += '?app.data.md5:{data} '.format(data=data)
                    ctifilter += '?app.data.sha256:{data} '.format(data=data)
                    ctifilter += '?http.body.data.md5:{data} '.format(data=data)
                    ctifilter += '?http.body.data.sha256:{data} '.format(data=data)
                    #ctifilter += '?http.body.data.domhash:{data} '.format(data=data) #roadmap
                    ctifilter += '?http.header.data.md5:{data} '.format(data=data)
                    ctifilter += '?http.header.data.sha256:{data} '.format(data=data)
                    ctifilter += '?favicon.data.md5:{data} '.format(data=data)
                    ctifilter += '?favicon.data.sha256:{data} '.format(data=data)
                    ctifilter += '?ssh.fingerprint.md5:{data} '.format(data=data)
                    ctifilter += '?ssh.fingerprint.sha1:{data} '.format(data=data)
                    ctifilter += '?ssh.fingerprint.sha256:{data} '.format(data=data)
                    ctifilter += '?hassh.fingerprint.md5:{data} '.format(data=data)
                    ctifilter += '?tcp.fingerprint.md5:{data} '.format(data=data)
                    ctifilter += '?ja4t.fingerprint.md5:{data} '.format(data=data)
                    #ctifilter += '?ja3s.fingerprint.md5:{data} '.format(data=data) #roadmap
                    #ctifilter += '?ja4s.fingerprint.md5:{data} '.format(data=data) #roadmap
                    #ctifilter += '?jarm.fingerprint.md5:{data} '.format(data=data) #roadmap
                    #ctifilter += '?jarm.ja3s.md5:{data} '.format(data=data) #roadmap
                elif self.data_type == "autonomous-system":
                    ctifilter += 'ip.asn:{asn} '.format(asn=data)
                elif self.data_type == "other":
                    try:
                        splitted = data.split(':')
                        splitsize = len(splitted)
                        port = int(splitted[splitsize-1])
                        ip = str(splitted[0])
                        #sanity check for IP, but not a full valid IP check as the API will do final checks anyway
                        #TODO handle vhost/fqdn parsing for other data_type
                        if splitsize  > 2 and splitsize < 10:
                            #could be IPv6
                            i = 0
                            ip = ""
                            for octet in splitted:
                                i += 1
                                if i < splitsize - 1 :
                                    ip += octet + ":"
                                elif i == splitsize - 1:
                                    ip += octet
                        elif splitsize == 2:
                            test = ip.split('.') 
                            if len(test) < 4:
                                raise OtherError("Unable to parse observable {other} as type other".format(other=data))        
                        else:
                            raise OtherError("Unable to parse observable {other} as type other".format(other=data))
                        ctifilter += 'ip.dest:{ip} tcp.dest:{port} '.format(ip=ip,port=port)
                    except:
                        raise OtherError("Unable to parse observable {other} as type other".format(other=data))
                        
                ctifilter += self.time_filter
                oql = 'category:{category} '.format(category=self.onyphe_category) + ctifilter
                results = self.onyphe_client.search_oql(oql)
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

        except Exception as e:
            self.unexpectedError(e)


if __name__ == "__main__":
    OnypheAnalyzer().run()
