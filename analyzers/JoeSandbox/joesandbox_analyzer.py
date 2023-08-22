#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer

import zipfile
import os 
import base64
import io
import requests
import time
import json
from jbxapi import JoeSandbox

def get_files(folder):
    # function to get all files in a folder sorted
    
    # get the path of the files
    files = [f"{file}" for file in os.listdir(folder)]
    # split <filename>.<extention>
    for i in range(len(files)):
        files[i]=files[i].split('.')
    # sort by <filename> numerically
    files.sort(key=lambda x: int(x[0]))
    # merge <folder>/<filename>.<extention>
    for i in range(len(files)):
        files[i]=folder+"/"+files[i][0]+"."+files[i][1]
    return files    
 

class JoeSandboxAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.url = self.get_param("config.url", None, "JoeSandbox url is missing")
        if self.get_param("config.key"):
            apikey = self.get_param("config.key")
        else:
            apikey = self.get_param(
                "config.apikey", None, "JoeSandbox API key is missing"
            )
        self.service = self.get_param(
            "config.service", None, "JoeSandbox service is missing"
        )
        self.analysistimeout = self.get_param("config.analysistimeout", 30 * 60, None)
        self.networktimeout = self.get_param("config.networktimeout", 30, None)
        self.images = self.get_param("config.images", False, None)
        self.HTML_report = self.get_param("config.HTML_report", False, None)
        self.observables = self.get_param("config.observables", False, None)
        self.joe = JoeSandbox(apikey, self.url, verify_ssl=False, accept_tac=True)

    def summary(self, raw):
        taxonomies = []
        namespace = "JSB"
        predicate = "Report"

        r = raw["detection"]

        value = "{}/{}".format(r["score"], r["maxscore"])

        if r["clean"]:
            level = "safe"
        elif r["suspicious"]:
            level = "suspicious"
        elif r["malicious"]:
            level = "malicious"
        else:
            level = "info"
            value = "Unknown"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts= []

        if self.observables:
            #IP
            if self.analysis['contacted']['ips']:
                for i in self.analysis['contacted']['ips']['ip']:
                    if(i['$']!='unknown'):
                        #print('ip ',str(i['$']))
                        artifacts.append(self.build_artifact('ip',str(i['$'])))       

            #URL
            if self.analysis['contacted']['domains']:
                for i in self.analysis['contacted']['domains']['domain']:
                    if(i['ip']!="unknown"):
                        #print('ip ',str(i['ip']))
                        artifacts.append(self.build_artifact('ip',str(i['ip'])))
                    #print('url',str(i['name']))
                    artifacts.append(self.build_artifact('url',str(i['name'])))
        
        #HTML report
        if self.HTML_report:
            if self.webid:
                webid = self.webid
                response = self.joe.analysis_download(webid, "html", run=0)
                with open('/tmp/'+str(response[0]), 'wb') as the_file:
                    the_file.write(response[1])
                artifacts.append(self.build_artifact('file',"/tmp/"+str(response[0])))
                os.remove('/tmp/'+str(response[0]))
        
        return artifacts
   
    def run(self):
        Analyzer.run(self)

        # file analysis with internet access
        if self.service == "file_analysis_inet":
            filename = self.get_param("filename", "")
            filepath = self.get_param("file", "")
            response = self.joe.submit_sample((filename, open(filepath, "rb")))
        elif self.service == "file_analysis_noinet":
            filename = self.get_param("filename", "")
            filepath = self.get_param("file", "")
            response = self.joe.submit_sample(
                (filename, open(filepath, "rb")), params={"internet-access": False}
            )
        # url analysis
        elif self.service == "url_analysis":
            response = self.joe.submit_url(self.get_data())

        else:
            self.error("Unknown JoeSandbox service")

        # Submit the file/url for analysis
        submission_id = response["submission_id"]

        # Wait for the analysis to finish
        finished = False
        tries = 0
        while not finished and tries <= self.analysistimeout / 60:
            time.sleep(60)
            response = self.joe.submission_info(submission_id)
            self.webid = response["analyses"][0]["webid"]
            if response["status"] == "finished":
                finished = True
            tries += 1
        if not finished:
            self.error("JoeSandbox analysis timed out")
        # Download the report
        response = self.joe.analysis_download(self.webid, "irjsonfixed", run=0)    
        self.analysis = json.loads(response[1].decode("utf-8")).get("analysis", None)

        if self.images: 
            # Download images
            zip_images = self.joe.analysis_download(self.webid, "shoots", run=0)
            zip_location = "/tmp/"+str(zip_images[0])
            zip_folder = "/tmp/images/"+str(zip_images[0])
            # write ziped images in /tmp
            with open(zip_location, 'wb') as file:
                file.write(zip_images[1])
            if not os.path.exists("/tmp/images/"):
                os.mkdir(path="/tmp/images/", mode = 0o744)
            if not os.path.exists(zip_folder):
                os.mkdir(path=zip_folder, mode = 0o744)
            # unzip images
            with zipfile.ZipFile(zip_location) as z:
                z.extractall(path=zip_folder)
            # remove ziped images (not needed anymore)
            os.remove(zip_location) 
            # put image in json
            images=[]
            for f in get_files(zip_folder):
                with open(str(f), mode='rb') as file:
                    images.append( base64.encodebytes(file.read()).decode('utf-8') )
                os.remove(f) 
            self.analysis["images"] = images
            # remove not needed files
            os.rmdir(zip_folder) 

        if self.analysis:
            self.analysis["htmlreport"] = (
                self.url + "analysis/" + str(self.analysis["id"]) + "/0/html"
            )
            self.analysis["pdfreport"] = (
                self.url + "analysis/" + str(self.analysis["id"]) + "/0/pdf"
            )
            self.report(self.analysis)
        else:
            self.error("Invalid output")


if __name__ == "__main__":
    JoeSandboxAnalyzer().run()

