#!/usr/bin/env python3
# encoding: utf-8
from autofocus import AutoFocusAPI, AFSample, AFServerError, AFClientError, AFSampleAbsent
from cortexutils.analyzer import Analyzer

# Define a class representing a search query in JSON format
class SearchJson(object):
    def __init__(self, search = ""):
        self.search = search
    def do_search(self):
        res = []
        for sample in AFSample.search(self.search):
            res.append({'metadata': sample.serialize(),
                        'tags': [tag.serialize() for tag in sample.__getattribute__('tags')]
            })
        return {'search': self.search, 'records': res}
        

# Define subclass for each predefined searches
class SearchJson_IP(SearchJson):
    def __init__(self,value):
        self.search={"operator":"all","children":[{"field":"alias.ip_address","operator":"contains","value":value}]}
    def do_search(self):
        return super(SearchJson_IP,self).do_search()
class SearchJson_Domain(SearchJson):
    def __init__(self,value):
        self.search={"operator":"all","children":[{"field":"alias.domain","operator":"contains","value":value}]}
    def do_search(self):
        return super(SearchJson_Domain,self).do_search()
class SearchJson_TAG(SearchJson):
    def __init__(self,value):
        self.search={"operator":"all","children":[{"field":"sample.tag","operator":"is in the list","value":[value]}]}
    def do_search(self):
        return super(SearchJson_TAG,self).do_search()
class SearchJson_URL(SearchJson):
    def __init__(self,value):
        self.search={"operator":"all","children":[{"field":"sample.tasks.http","operator":"is in the list","value":[value]}]}
    def do_search(self):
        return super(SearchJson_URL,self).do_search()
class SearchJson_Imphash(SearchJson):
    def __init__(self,value):
        self.search={"operator":"all","children":[{"field":"sample.imphash","operator":"is","value":value}]}
    def do_search(self):
        return super(SearchJson_Imphash,self).do_search()
class SearchJson_Mutex(SearchJson):
    def __init__(self,value):
        self.search={"operator":"all","children":[{"field":"sample.tasks.mutex","operator":"contains","value":value}]}
    def do_search(self):
        return super(SearchJson_Mutex,self).do_search()
class SearchJson_UserAgent(SearchJson):
    def __init__(self,value):
        self.search={"operator":"all","children":[{"field":"alias.user_agent","operator":"contains","value":value}]}
    def do_search(self):
        return super(SearchJson_UserAgent,self).do_search()

# Main analyzer
class AutoFocusAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam(
            'config.service', None, 'Service parameter is missing')
        self.autofocus_key = self.getParam(
            'config.apikey', None, 'Missing AutoFocus API key')

    def execute_autofocus_service(self):
        data = self.getData()
        AutoFocusAPI.api_key = self.autofocus_key
        if self.service == 'get_sample_analysis' and self.data_type in ['hash']:
            sample = AFSample.get(data)
            res = {'metadata': sample.serialize(),
                   'tags': [tag.serialize() for tag in sample.__getattribute__('tags')],
                   'analysis': {}
            }
            for analyse in sample.get_analyses():
                analysis_type = analyse.__class__.__name__
                if analysis_type not in res['analysis']:
                    res['analysis'][analysis_type] = []
                res['analysis'][analysis_type].append(analyse.serialize())
            return res
        elif self.service == 'search_ioc' and self.data_type in ['ip']:
            searchIP = SearchJson_IP(data)
            return searchIP.do_search()
        elif self.service == 'search_ioc' and self.data_type in ['domain','fqdn']:
            searchDomain = SearchJson_Domain(data)
            return searchDomain.do_search()
        elif self.service == 'search_ioc' and self.data_type in ['mutex']:
            searchMutex = SearchJson_Mutex(data)
            return searchMutex.do_search()
        elif self.service == 'search_ioc' and self.data_type in ['imphash']:
            searchImpash = SearchJson_Imphash(data)
            return searchImpash.do_search()
        elif self.service == 'search_ioc' and self.data_type in ['tag']:
            searchTag = SearchJson_TAG(data)
            return searchTag.do_search()
        elif self.service == 'search_ioc' and self.data_type in ['url']:
            searchURL = SearchJson_URL(data)
            return searchURL.do_search()
        elif self.service == 'search_ioc' and self.data_type in ['user-agent']:
            searchUserAgent = SearchJson_UserAgent(data)
            return searchUserAgent.do_search()
        elif self.service == 'search_json' and self.data_type in ['other']:
            search = SearchJson(data)
            return search.do_search()
        else:
            self.error('Unknown AutoFocus service or invalid data type')

    def summary(self, raw):
        # taxonomy = {"level": "info", "namespace": "PaloAltoNetworks", "predicate": "AutoFocus", "value": 0}
        taxonomies = []
        level = "info"
        namespace = "PaloAltoNetworks"
        predicate = "AutoFocus"

        if "metadata" in raw:
            value = "Sample found"
        elif "records" in raw:
            value = "{} sample(s) found".format(len(raw["records"]))
        else:
            value = ""

        taxonomies.append(self.build_taxonomy(level,namespace,predicate,value))

        return {'taxonomies': taxonomies}


    def run(self):
        try:
            records = self.execute_autofocus_service()
            self.report(records)

        except AFSampleAbsent as e: # Sample not in Autofocus
            self.error('Unknown sample in Autofocus')
        except AFServerError as e: # Server error
            self.unexpectedError(e)
        except AFClientError as e: # Client error
            self.unexpectedError(e)
        except Exception: # Unknown error
            self.unexpectedError("Unknown error while running Autofocus analyzer")

if __name__ == '__main__':
    AutoFocusAnalyzer().run()
