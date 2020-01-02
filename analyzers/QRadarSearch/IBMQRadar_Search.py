#!/usr/bin/env python
# encoding: utf-8
import requests
import time
from collections import OrderedDict
from datetime import datetime
from cortexutils.analyzer import Analyzer
import logging
import os
import urllib
import json
from urllib3.exceptions import InsecureRequestWarning,SubjectAltNameWarning

#Allow Debug logging without interfering with the Analyzer
debug = False

if debug:
    logging.basicConfig(filename='{}/QRadarSearch.log'.format(
                                    os.path.dirname(os.path.realpath(__file__))),
                                    level='DEBUG', 
                                    format='%(asctime)s\
                                           %(levelname)s\
                                           %(message)s')

#Create a variable with the current time in milliseconds
current_time = time.time() * 1000

class IBMQRadarAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        
        #Retrieve configuration from config file
        self.service = self.get_param(
            'config.service', None, 'Service parameter is missing')
        self.url = self.get_param('config.url', None, 'Missing API url')
        self.key = self.get_param('config.key', None, 'Missing API key')
        self.proxies = self.get_param('config.proxy', None)
        self.verify = self.get_param('config.verify', None)
        self.search_timeout = self.get_param('config.search_timeout', 3600)
        if self.service == "automated":
            self.search_limit = self.get_param('config.search_limit', 1)
        elif self.service == "manual":
            self.search_limit = self.get_param('config.search_limit', 7)
        self.rs_switchover = self.get_param('config.rs_switchover', 24)
        #Loading (Custom) Fields
        self.http_method_field = self.get_param('config.url_http_method_field')
        self.fqdn_field = self.get_param('config.url_fqdn_field')
        self.root_domain_field = self.get_param('config.url_root_domain_field')
        self.url_field = self.get_param('config.url_field')
        self.mail_recipient_field = self.get_param('config.mail_recipient_field')
        self.mail_sender_field = self.get_param('config.mail_sender_field')
        self.mail_subject_field = self.get_param('config.mail_subject_field')
        self.computer_field = self.get_param('config.computer_field')
        self.md5_hash_field = self.get_param('config.md5_hash_field')
        self.sha1_hash_field = self.get_param('config.sha1_hash_field')
        self.sha256_hash_field = self.get_param('config.sha256_hash_field')
        self.image_field = self.get_param('config.image_field')
        #Convert to milliseconds to compare with QRadar data
        self.rs_switchover_ms = self.rs_switchover * 3600000
        
        if not self.verify:
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings(category=SubjectAltNameWarning)
        
        #Headers
        self.headers = {'SEC': self.key}
        self.headers['Accept'] = 'application/json'
        self.headers['Content-Type'] = 'application/json'
    
    #Function to handle QRadar requests
    def qradar_request(self, http_type, uri, response_code):
        logging.debug("Request to be fired: {} {} Headers: {} Verify: {}".format(http_type, uri, self.headers, self.verify))
        uri = urllib.quote(uri)
        request = self.url + uri
        
        #Use error handling to capture any exceptions
        try:
            #Check the HTTP type to create the request accordingly
            if http_type == "get":
                response = requests.get(request, headers=self.headers,
                                    proxies=self.proxies,
                                    verify=self.verify)
            elif http_type == "post":
                response = requests.post(request, headers=self.headers,
                                    proxies=self.proxies,
                                    verify=self.verify)
            
            elif http_type == "delete":
                response = requests.delete(request, headers=self.headers,
                                    proxies=self.proxies,
                                    verify=self.verify)            
            
            else: 
                self.error("Error: %s is not a supported http type" % http_type)
            #Capture the json response and return it
            qr_response = response.json(object_pairs_hook=OrderedDict)
            
            #Check if the response code is as expected, else generate an error
            if response.status_code == response_code:
                return qr_response
            else:
                self.error("QRadar reponse code: {} error: {}".format(response.status_code,qr_response))
        except requests.exceptions.RequestException as e:
            self.error("Error: {}".format(e))
    
    #Check the status of the search
    def qradar_check_search(self, query_type, qr_search_array, search_observable, delete=True):
        qr_return_object = {}
        #loop through searches
        for qr_search in qr_search_array:
            
            #Default values
            self.qr_search_completed = False
            self.runtime = 0
            
            #Create a loop to wait for the search to finish (if it is not finished already)
            while self.qr_search_completed == False:
                #Retrieve status from QRadar
                results = self.qradar_request("get", "/api/ariel/searches/{}".format(qr_search[1]), 200)
                qr_search_status = results['status']
                logging.debug("Waiting for search to be completed... Current status: {}".format(qr_search_status))
                
                #If the search is completed... continue, else keep the loop open until the timeout is reached
                if qr_search_status == "COMPLETED":
                    self.qr_search_completed = True
                elif self.runtime > self.search_timeout:
                    self.error('Search timed out. Please check "{}" manually and optimize the search if it happens a lot'.format(qr_search[1]))
                elif qr_search_status in ["EXECUTE", "SORTING", "WAIT"]:
                    sleep_in_seconds = 10
                    self.runtime += sleep_in_seconds
                    time.sleep(sleep_in_seconds)
                else:
                    self.error('Unknown search status returned: {} Please check "{}" manually'.format(qr_search_status, qr_search[1]))

        
        #Return the results
        for qr_search in qr_search_array:
            qr_return_object[qr_search[0]] = {}
            #Add search query to the results
            qr_return_object[qr_search[0]]['search_query'] = qr_search[2]
            if self.qr_search_completed == True:
                logging.debug("Retrieving search results for search")
                # Retrieve the results
                search_results = self.qradar_request("get", "/api/ariel/searches/{}/results".format(qr_search[1]), 200)
                #remove the search when done with it
                if delete:
                    self.qradar_request("delete", "/api/ariel/searches/{}".format(qr_search[1]), 202)
                if 'events' in search_results:
                    qr_results = search_results['events']
                if 'flows' in search_results:
                    qr_results = search_results['flows']
                logging.debug("Results of the search %s" % str(qr_results))
                if query_type == 'count':
                    #By default we can expect no results to be found, if we do we change it to True
                    qr_return_object[qr_search[0]]['result_found'] = False
                    qr_return_object[qr_search[0]]['result_count'] = 0
                    for qr_result in qr_results:
                        if search_observable == qr_result['aql_result']:
                            qr_return_object[qr_search[0]]['first_seen'] = qr_result['first_seen']
                            qr_return_object[qr_search[0]]['last_seen'] = qr_result['last_seen']
                            if qr_result['COUNT']:
                                qr_return_object[qr_search[0]]['result_count'] = qr_result['COUNT']
                            qr_return_object[qr_search[0]]['result_found'] = True
                if query_type == 'events':
                    qr_return_object[qr_search[0]]['results'] = qr_results
                        
        return qr_return_object
    
    #Function to perform searches based on a IOC value
    def qradar_ioc_search(self, search_type, observable_type, data):
        
        qr_result_object = {}
        qr_search_config = {}
        
        ################################################IP queries######################################################
        ################################################################################################################
        
        qr_search_config['ip'] = {'count_queries': [], 'event_queries': [], 'reference_set': ''}
        
        #Reference set used for reference set searches
        qr_search_config['ip']['reference_set'] = "qthi-ip"
        
        #AQL queries for counts to check if an observable is hit
        qr_search_config['ip']['count_queries'].append([
            'Source ip in logs',
            "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, sourceip AS aql_result, COUNT(*) FROM events WHERE sourceip == '{}' GROUP BY aql_result LAST {} DAYS".format(data, self.search_limit)
            ])
        qr_search_config['ip']['count_queries'].append([
            'Destination ip in logs',
            "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, destinationip AS aql_result, COUNT(*) FROM events WHERE destinationip == '{}' GROUP BY aql_result LAST {} DAYS".format(data, self.search_limit)
        ])
        qr_search_config['ip']['count_queries'].append([
            'Source ip in flows',
            "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, sourceip AS aql_result, COUNT(*) FROM flows WHERE sourceip == '{}' GROUP BY aql_result LAST {} DAYS".format(data, self.search_limit)
        ])
        qr_search_config['ip']['count_queries'].append([
            'Destination ip in flows',
            "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, destinationip AS aql_result, COUNT(*) FROM flows WHERE destinationip == '{}' GROUP BY aql_result LAST {} DAYS".format(data, self.search_limit)
        ])
        
        #AQL queries to return events when observables are hit
        qr_search_config['ip']['event_queries'].append([
            'Source ip in logs',
            "SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm') AS timestamp, sourceip, sourceport, destinationip, destinationport FROM events WHERE sourceip == '{}' LIMIT 50 LAST {} DAYS".format(data, self.search_limit)
            ])
        qr_search_config['ip']['event_queries'].append([
            'Destination ip in logs',
            "SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm') AS timestamp, sourceip, sourceport, destinationip, destinationport FROM events WHERE destinationip == '{}' LIMIT 50 LAST {} DAYS".format(data, self.search_limit)
            ])
        qr_search_config['ip']['event_queries'].append([
            'Source ip in flows',
            "SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm') AS timestamp, sourceip, sourceport, destinationip, destinationport FROM flows WHERE sourceip == '{}' LIMIT 50 LAST {} DAYS".format(data, self.search_limit)
            ])
        qr_search_config['ip']['event_queries'].append([
            'Destination ip in flows',
            "SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm') AS timestamp, sourceip, sourceport, destinationip, destinationport FROM flows WHERE destinationip == '{}' LIMIT 50 LAST {} DAYS".format(data, self.search_limit)
            ])
            
        ################################################Domain queries######################################################
        ################################################################################################################
        qr_search_config['domain'] = {'count_queries': [], 'event_queries': [], 'reference_set': ''}
        
        #Reference set used for reference set searches
        qr_search_config['domain']['reference_set'] = "qthi-domain"
        
        #AQL queries for counts to check if an observable is hit
        qr_search_config['domain']['count_queries'].append([
            'Domain in logs',
            "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE \"{}\" == '{}' GROUP BY aql_result LAST {} DAYS".format(self.root_domain_field, self.root_domain_field, data, self.search_limit)
            ])
            
        #AQL queries to return events when observables are hit
        qr_search_config['domain']['event_queries'].append([
            'Domain in logs',
            "SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm') AS timestamp, sourceip, \"{}\", \"{}\", \"{}\" FROM events WHERE \"{}\" == '{}' LIMIT 50 LAST \"{}\" DAYS".format(self.http_method_field, self.url_field, self.root_domain_field, self.root_domain_field, data, self.search_limit)
            ])
        
        ################################################FQDN queries######################################################
        ################################################################################################################
        qr_search_config['fqdn'] = {'count_queries': [], 'event_queries': [], 'reference_set': ''}
        
        #Reference set used for reference set searches
        qr_search_config['fqdn']['reference_set'] = "qthi-fqdn"
        
        #AQL queries for counts to check if an observable is hit
        qr_search_config['fqdn']['count_queries'].append([
            'Fqdn in logs',
            "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE \"{}\" == '{}' GROUP BY aql_result LAST {} DAYS".format(self.fqdn_field, self.fqdn_field, data, self.search_limit)
            ])
            
        #AQL queries to return events when observables are hit
        qr_search_config['fqdn']['event_queries'].append([
            'Fqdn in logs',
            "SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm') AS timestamp, sourceip, \"{}\", \"{}\", \"{}\" FROM events WHERE \"{}\" == '{}' LIMIT 50 LAST {} DAYS".format(self.http_method_field, self.fqdn_field, self.root_domain_field, self.fqdn_field, data, self.search_limit)
            ])

        ################################################Url queries######################################################
        ################################################################################################################
        qr_search_config['url'] = {'count_queries': [], 'event_queries': [], 'reference_set': ''}
        
        #Reference set used for reference set searches
        qr_search_config['url']['reference_set'] = "qthi-url"
        
        #AQL queries for counts to check if an observable is hit
        qr_search_config['url']['count_queries'].append([
            'Url in logs',
            "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE \"{}\" == '{}' GROUP BY aql_result LAST {} DAYS".format(self.url_field, self.url_field, data, self.search_limit)
            ])
            
        #AQL queries to return events when observables are hit
        qr_search_config['url']['event_queries'].append([
            'Url in logs',
            "SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm') AS timestamp, sourceip, \"{}\", \"{}\" FROM events WHERE \"{}\" == '{}' LIMIT 50 LAST {} DAYS".format(self.http_method_field, self.url_field, self.url_field, data, self.search_limit)
            ])
        
        ################################################Mail queries######################################################
        ################################################################################################################
        qr_search_config['mail'] = {'count_queries': [], 'event_queries': [], 'reference_set': ''}
        
        #Reference set used for reference set searches
        qr_search_config['mail']['reference_set'] = "qthi-mail"
        
        #AQL queries for counts to check if an observable is hit
        qr_search_config['mail']['count_queries'].append([
            'Sender address in logs',
            "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE \"{}\" == '{}' GROUP BY aql_result LAST {} DAYS".format(self.mail_sender_field, self.mail_sender_field, data, self.search_limit)
            ])
        qr_search_config['mail']['count_queries'].append([
            'Recipient address in logs',
            "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE \"{}\" == '{}' GROUP BY aql_result LAST {} DAYS".format(self.mail_recipient_field, self.mail_recipient_field, data, self.search_limit)
            ])
            
        #AQL queries to return events when observables are hit
        qr_search_config['mail']['event_queries'].append([
            'Sender address in logs',
            "SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm') AS timestamp, \"{}\", \"{}\", \"{}\" FROM events WHERE \"{}\" == '{}' LIMIT 50 LAST {} DAYS".format(self.mail_recipient_field, self.mail_sender_field, self.mail_subject_field, self.mail_sender_field, data, self.search_limit)
            ])
        qr_search_config['mail']['event_queries'].append([
            'Recipient address in logs',
            "SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm') AS timestamp, \"{}\", \"{}\", \"{}\" FROM events WHERE \"{}\" == '{}' LIMIT 50 LAST {} DAYS".format(self.mail_recipient_field, self.mail_sender_field, self.mail_subject_field, self.mail_recipient_field, data, self.search_limit)
            ])
        
        ################################################Hash queries######################################################
        ################################################################################################################
        qr_search_config['hash'] = {'count_queries': [], 'event_queries': [], 'reference_set': ''}
        
        if observable_type == "hash":
            if len(data) == 32:
                #Reference set used for reference set searches
                qr_search_config['hash']['reference_set'] = "qthi-hash-md5"
                
                #AQL queries for counts to check if an observable is hit
                qr_search_config['hash']['count_queries'].append([
                    'Hash in logs',
                    "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE \"{}\" == '{}' GROUP BY aql_result LAST {} DAYS".format(self.md5_hash_field, self.md5_hash_field, data, self.search_limit)
                    ])
                    
                #AQL queries to return events when observables are hit
                qr_search_config['hash']['event_queries'].append([
                    'Hash in logs',
                    "SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm') AS timestamp, \"{}\", \"{}\", \"{}\" FROM events WHERE \"MD5 Hash\" == '{}' LIMIT 50 LAST {} DAYS".format(self.computer_field, self.md5_hash_field, self.image_field, self.md5_hash_field, data, self.search_limit)
                    ])
                    
            elif len(data) == 40:
                #Reference set used for reference set searches
                qr_search_config['hash']['reference_set'] = "qthi-hash-sha1"
                
                #AQL queries for counts to check if an observable is hit
                qr_search_config['hash']['count_queries'].append([
                    'Hash in logs',
                    "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE \"{}\" == '{}' GROUP BY aql_result LAST {} DAYS".format(self.sha1_hash_field, self.sha1_hash_field, data, self.search_limit)
                    ])
                    
                #AQL queries to return events when observables are hit
                qr_search_config['hash']['event_queries'].append([
                    'Hash in logs',
                    "SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm') AS timestamp, \"{}\", \"{}\", \"{}\" FROM events WHERE \"{}\" == '{}' LIMIT 50 LAST {} DAYS".format(self.computer_field, self.sha1_hash_field, self.image_field, self.sha1_hash_field, data, self.search_limit)
                    ])
            
            elif len(data) == 64:
                #Reference set used for reference set searches
                qr_search_config['hash']['reference_set'] = "qthi-hash-sha2"
                
                #AQL queries for counts to check if an observable is hit
                qr_search_config['hash']['count_queries'].append([
                    'Hash in logs',
                    "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE \"{}\" == '{}' GROUP BY aql_result LAST {} DAYS".format(self.sha256_hash_field, self.sha256_hash_field, data, self.search_limit)
                    ])
                    
                #AQL queries to return events when observables are hit
                qr_search_config['hash']['event_queries'].append([
                    'Hash in logs',
                    "SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm') AS timestamp, \"{}\", \"{}\", \"{}\" FROM events WHERE \"{}\" == '{}' LIMIT 50 LAST {} DAYS".format(self.computer_field, self.sha256_hash_field, self.image_field, self.sha256_hash_field, data, self.search_limit)
                    ])
            
            else:
                self.error('Hash length does not match any of the supported lengths. This is probably an unsupported hash type. (Supported: md5, SHA1, SHA256)')

                
        #Make direct search the default option
        direct_search_required = True
        
        #Check if ioc is in reference set
        if search_type == "automated":
            #Temporarily add range header
            self.headers['Range'] = "items=0-1000000"
            #print("headers 1: " + str(self.headers))
            results = self.qradar_request("get","/api/reference_data/sets/{}?filter=value%3D%22{}%22".format(qr_search_config[observable_type]['reference_set'], data ), 200)
            #Remove range header
            del self.headers['Range']
            
            #Determine if a direct search or RS search is required
            if 'data' in results:
                for rs_entry in results['data']:
                    #If the value is present in the reference set and the first time seen (date on which the observable was first added to the list) is less than 24 hours, direct search must be used
                    logging.debug("{}: Time from First Seen: {} Current time: {} Difference: {}".format(str(rs_entry['value']), str(rs_entry.get('first_seen')), str(current_time), str(current_time - rs_entry['first_seen'])))
                    #The line below breaks the script when trying to convert a unicode url to ascii, do not try to make ascii from unicode urls, without converting unknown characters
                    logging.debug("Checking if {} equals {}".format(data, rs_entry['value']))
                    if data.lower() == rs_entry['value']:
                        observable_present_in_rs = True
                        logging.debug("A match is found, checking time added")
                        if (int(current_time - rs_entry['first_seen'])) > int(self.rs_switchover_ms):
                            logging.debug("The observable is present for longer than a day, disabling direct search")
                            direct_search_required = False
                        break
                    else:
                        observable_present_in_rs = False
                        #direct_search_required = True
            else: 
                #direct_search_required = True
                observable_present_in_rs = False
            
            logging.debug("Direct search is {}".format(str(direct_search_required)))
            #Add the data to the reference set
            if not observable_present_in_rs:
                self.qradar_request("post","/api/reference_data/sets/{}?value={}".format(qr_search_config[observable_type]['reference_set'],data), 200)
        
        ############################# Regular Search #############################
        #If ioc is not in reference set add it and perform a search for the ioc
        if direct_search_required or search_type == "manual":
            #Create a search for occurences in QRadar
            self.qr_searches = []
            for aql_query in qr_search_config[observable_type]['count_queries']:
                raw_results = self.qradar_request("post","/api/ariel/searches?query_expression={}".format(aql_query[1]), 201)
                self.qr_searches.append([aql_query[0], raw_results['search_id'], aql_query[1]])
            
            #Check search status for searches in array
            qr_result_object = self.qradar_check_search('count', self.qr_searches, data)
            
            #Check to see if there are any hits and retrieve events when so
            logging.debug ("Intermediate search results: %s" % qr_result_object)
            qr_result_object = self.check_for_hits(data, qr_result_object, observable_type, qr_search_config)
        
        ############################# Reference Set Search #############################
        else:
            self.qr_searches = []
            #Open file to write uuids
            self.uuid_work_file = open('/tmp/{}-uuid_work_file.txt'.format(qr_search_config[observable_type]['reference_set']),'r')
            for line in self.uuid_work_file:
                line = line.strip('\n')
                self.qr_searches.append(json.loads(line))
            self.uuid_work_file.close()

            #Check search status for searches in array
            qr_result_object = self.qradar_check_search('count', self.qr_searches, data, delete=False)
            
            #Check to see if there are any hits and retrieve events when so
            logging.debug ("Intermediate search results: %s" % qr_result_object)
            qr_result_object = self.check_for_hits(data, qr_result_object, observable_type, qr_search_config)
            
        return qr_result_object
    
    def check_for_hits(self, data, intermediate_results, observable_type, qr_search_config):
        #When results are found, perform a query to retrieve the actual events
        for search_id,query_results in intermediate_results.iteritems():
            get_events = False
            if query_results['result_found']:
                get_events = True
        
        if get_events:
            logging.debug("Retrieving events for found ioc")
            self.qr_searches = []
            for aql_query in qr_search_config[observable_type]['event_queries']:
                raw_results = self.qradar_request("post","/api/ariel/searches?query_expression={}".format(aql_query[1]), 201)
                self.qr_searches.append([aql_query[0], raw_results['search_id'], aql_query[1]])
            
            event_results = self.qradar_check_search('events', self.qr_searches, data)
            logging.debug ("Returning search results for events: %s" % event_results)
            
            #Add the events to the results
            for s,r in intermediate_results.iteritems(): 
                r.update(event_results[s])
                intermediate_results[s] = r
                
        return intermediate_results
    
    #Function to provide summary information. This function is used by The Hive for its reports
    def summary(self, raw):
        taxonomies = []
        namespace = "IBMQRadar"
        predicate = "Result count"
        self.count = 0
        for search,search_result in raw.iteritems():
            self.count += search_result['result_count']
        results = self.count
        
        if results > 0:
            level = "suspicious"
        else:
            level = "info"
        
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, "{}".format(results)))

        logging.debug("taxonomies content: %s" % taxonomies)
        return {"taxonomies": taxonomies}

    #Default Cortex analyzer trigger (do not modify)
    def run(self):

        if self.service == 'automated' or self.service == 'manual':
            self.data_type = self.get_param('dataType', None, 'Data is missing')
            self.data = self.get_param('data', None, 'Data is missing')
            if self.data_type in ['ip','fqdn','domain','url',"mail","hash"]:
                #Perform QRadar Search
                results = self.qradar_ioc_search(self.service, self.data_type, self.data)
                self.report(results)
            else:
                self.error('Invalid data type')
        else:
            self.error('Invalid service')


if __name__ == '__main__':
    IBMQRadarAnalyzer().run()

