#!/usr/bin/env python3
# encoding: utf-8


import splunklib.client as client
from time import sleep
from cortexutils.analyzer import Analyzer
import splunklib.results as results
import splunklib
import urllib
import re
from datetime import datetime


class Splunk(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.HOST = self.getParam('config.host', None, 'Host parameter is missing')
        self.PORT = self.getParam('config.port', None, 'Port parameter is missing')
        self.PORT_GUI = self.getParam('config.port_gui', None, 'GUI port parameter is missing')
        self.USERNAME = self.getParam('config.username', None, 'Username parameter is missing')
        self.PASSWORD = self.getParam('config.password', None, 'Password parameter is missing')
        self.OWNER = self.getParam('config.owner', None, 'Owner parameter is missing')
        self.APP = self.getParam('config.application', None, 'Application parameter is missing')
        self.SAVEDSEARCHES = self.getParam('config.saved_searches', None, 'At least one Splunk savedsearch name is required')
        self.EARLIEST = self.getParam('config.earliest_time', None)
        self.LATEST = self.getParam('config.latest_time', None)
        self.MAX_COUNT = self.getParam('config.max_count', None)

    # Create a Service instance and log in
    def SplunkConnect(self):
        try:
            self.service = client.connect(
                host=self.HOST,
                port=self.PORT,
                username=self.USERNAME,
                password=self.PASSWORD,
                owner=self.OWNER,
                app=self.APP)
        except Exception as e:
            self.unexpectedError(e)


    # Execute a saved search
    def SplunkSearch(self, **kwargs_savedsearch):

        # Get all saved searches
        saved_searches = self.SAVEDSEARCHES

        # Set time search if mentionned
        if (self.EARLIEST is not None):
            kwargs_savedsearch["dispatch.earliest_time"] = self.EARLIEST
        if (self.LATEST is not None):
            kwargs_savedsearch["dispatch.latest_time"] = self.LATEST


        jobs = {}
        for saved_search in saved_searches:
            # Execute every savedsearch with the needed arguments
            job = self.service.saved_searches[saved_search].dispatch(**kwargs_savedsearch)
            jobs[saved_search] = {"job": job, "search": "", "results": {}, "eventCount": 0, "resultCount": 0}

        jobs_running = len(jobs)

        # A savedsearch returns the job's SID right away, so we need to poll for completion
        # Wait for the jobs until they are all done
        while jobs_running != 0:
            # Check every 4 seconds
            sleep(4)
            jobs_running = len(jobs)
            for saved_search in jobs:
                job = jobs[saved_search]["job"]
                if job.is_done():
                   try:
                       jobs[saved_search]["results"] = results.ResultsReader(job.results(count=self.MAX_COUNT))
                       jobs[saved_search]["is_failed"] = False

                   except splunklib.binding.HTTPError as e:
                       jobs[saved_search]["results"] = [str(e)]
                       jobs[saved_search]["is_failed"] = True


                   finally:
                       jobs[saved_search]["link"] = "http://"+self.HOST+":"+self.PORT_GUI+"/fr-FR/app/"+self.APP+"/search?sid="+job["sid"]
                       jobs[saved_search]["eventCount"] = int(job["eventCount"])
                       jobs[saved_search]["resultCount"] = int(job["resultCount"])
                       jobs[saved_search]["searchEarliestTime"] = datetime.utcfromtimestamp(round(float(job["searchEarliestTime"]))).strftime("%c")
                       jobs[saved_search]["searchLatestTime"] = datetime.utcfromtimestamp(round(float(job["searchLatestTime"]))).strftime("%c")
                       jobs[saved_search]["search"] = job["search"]
                       jobs_running -= 1 

        # Get the results and display them
        savedSearchResults = []

        # Process all saved searches
        # Each result is under the name of the saved search
        for saved_search in jobs:
            jobResult = {}
            dataResults = {}
            job_infos = jobs[saved_search]
            index = 0
            fieldLevelInfo = 0
            fieldLevelSafe = 0
            fieldLevelSuspicious = 0
            fieldLevelMalicious = 0

            try:
              for result in job_infos["results"]:
                  dataResults[index] = result
                  # Check if a field "level" exists
                  if "level" in result:
                      # if so, count the values if it's info,safe,suspicious,malicious
                      if result["level"] == "info":
                          fieldLevelInfo += 1
                      if result["level"] == "safe":
                          fieldLevelSafe += 1
                      if result["level"] == "suspicious":
                          fieldLevelSuspicious += 1
                      if result["level"] == "malicious":
                          fieldLevelMalicious += 1

                  index += 1
              if fieldLevelInfo+fieldLevelSafe+fieldLevelSuspicious+fieldLevelMalicious > 0 :
                  jobResult["levels"] = {"info": fieldLevelInfo, "safe": fieldLevelSafe, "suspicious": fieldLevelSuspicious, "malicious": fieldLevelMalicious}
              jobResult["results"] = dataResults

            except Exception as e:
              jobResult["error"] = "Parsing results error for this search, special character ? : "+str(e)

            finally:
              jobResult["length"] = index
              jobResult["failed"] = job_infos["is_failed"]
              jobResult["link"] = job_infos["link"]
              jobResult["eventCount"] = job_infos["eventCount"]
              jobResult["resultCount"] = job_infos["resultCount"]
              jobResult["searchEarliestTime"] = job_infos["searchEarliestTime"]
              jobResult["searchLatestTime"] = job_infos["searchLatestTime"]

              
              if jobResult["resultCount"] > self.MAX_COUNT:
                  jobResult["note"] = "Only the first {} results were recovered over {} to avoid any trouble on TheHive/Cortex. This parameter (max_count) can be changed in the analyzer configuration.".format(self.MAX_COUNT, jobResult["resultCount"])

              jobResult["search"] = job_infos["search"]
              jobResult["savedsearch"] = saved_search

              savedSearchResults.append(jobResult)
        
        finalResult = {"savedsearches": savedSearchResults}

        # Build the report 
        self.report(finalResult)


    def SplunkURLSearch(self, data):


        if self.data_type == 'url':
            # Check if it's a valid URL/domain and extract the domain automatically if needed
            try:
                regex = re.compile(r"^(?:https?:\/\/)?([^\/|\?|\&|\$|\+|\,|\:|\;|\=|\@|\#]+)(?:\/.*)?$")
                match = regex.search(data)
                if match is not None:
                    domain = match.group(1)
                else:
                    self.error('Malformed URL. Could not extract domain from URL.')

            except Exception as e:
                self.error('Unexpected error: ' + str(e))
        
            kwargs_savedsearch = {"args.url": data, "args.domain": domain, "args.type": self.data_type, "output_mode": "xml"}

        self.SplunkSearch(**kwargs_savedsearch)


    def SplunkIPSearch(self, data):

        # Check if it's a good IPv4 IP address
        try:
            regex = re.compile(r"^((?:([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))$")
            match = regex.search(data)
            if match is not None:
                domain = match.group(1)
            else:
                self.error('Malformed IPv4')

        except Exception as e:
            self.error('Unexpected error: ' + str(e))
        
        kwargs_savedsearch = {"args.ip": data, "args.type": self.data_type, "output_mode": "xml"}

        self.SplunkSearch(**kwargs_savedsearch)


    def SplunkOtherSearch(self, data):
 
        kwargs_savedsearch = {"args."+self.data_type: data, "args.type": self.data_type, "output_mode": "xml"}
        self.SplunkSearch(**kwargs_savedsearch)


    def summary(self, raw):
        taxonomies = []
        value = 0
        namespace = "Splunk"
        taxonomyResults = {"level": "safe", "namespace": namespace, "predicate": "Results", "value": 0}

        # (Optional) These taxonomies will be added only if a field "level" is found
        taxonomyInfo = {"level": "info", "namespace": namespace, "predicate": "Info", "value": 0}
        taxonomySafe = {"level": "safe", "namespace": namespace, "predicate": "Safe", "value": 0}
        taxonomySuspicious = {"level": "suspicious", "namespace": namespace, "predicate": "Suspicious", "value": 0}
        taxonomyMalicious = {"level": "malicious", "namespace": namespace, "predicate": "Malicious", "value": 0}

        # Process all requests with the given taxonomies
        for savedsearch in raw["savedsearches"]:
            taxonomyResults["value"] += savedsearch["resultCount"]  
            
            if "levels" in savedsearch:
                levels = savedsearch["levels"]
                taxonomyInfo["value"] += levels["info"]    
                taxonomySafe["value"] += levels["safe"]    
                taxonomySuspicious["value"] += levels["suspicious"]    
                taxonomyMalicious["value"] += levels["malicious"]    

        # Add results taxonomy anyway
        # Change the level if there is any result
        if taxonomyResults["value"]>0:
            taxonomyResults["level"] = "suspicious"
        else:
            taxonomyResults["value"] = "None"
        taxonomies.append(self.build_taxonomy(taxonomyResults["level"], taxonomyResults["namespace"], taxonomyResults["predicate"], taxonomyResults["value"]))

        # Only add optional taxonomies if they are not null
        if taxonomyInfo["value"] > 0:
            taxonomies.append(self.build_taxonomy(taxonomyInfo["level"], taxonomyInfo["namespace"], taxonomyInfo["predicate"], taxonomyInfo["value"]))
        if taxonomySafe["value"] > 0:
            taxonomies.append(self.build_taxonomy(taxonomySafe["level"], taxonomySafe["namespace"], taxonomySafe["predicate"], taxonomySafe["value"]))
        if taxonomySuspicious["value"] > 0:
            taxonomies.append(self.build_taxonomy(taxonomySuspicious["level"], taxonomySuspicious["namespace"], taxonomySuspicious["predicate"], taxonomySuspicious["value"]))
        if taxonomyMalicious["value"] > 0:
            taxonomies.append(self.build_taxonomy(taxonomyMalicious["level"], taxonomyMalicious["namespace"], taxonomyMalicious["predicate"], taxonomyMalicious["value"]))


        return {"taxonomies": taxonomies}


    def run(self):
        Analyzer.run(self)
        data = self.getParam('data', None, 'Data is missing')
        self.SplunkConnect()
        if self.data_type == 'url':
            self.SplunkURLSearch(data)
        elif self.data_type == 'ip':
            self.SplunkIPSearch(data)
        elif self.data_type in ['user-agent','uri_path','domain','fqdn','hash','file','filename','mail_subject','mail','email','registry','other']:
            self.SplunkOtherSearch(data)
        else:
            self.error('Invalid Datatype')

if __name__ == '__main__':
    Splunk().run() 
