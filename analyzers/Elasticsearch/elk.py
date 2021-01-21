#!/usr/bin/env python3

from elasticsearch import Elasticsearch
from cortexutils.analyzer import Analyzer
import dateutil.parser
from datetime import datetime
import pytz

# utils
import operator

class Hit:
    def __init__(self,hitindex,hitid,process_parent_name,process_name,process_args,user_name,host_name,timestamp,time,\
                 destination_ip,destination_port,source_ip,source_port,source_user_name,url_domain,url_path,url_full,\
                 rule_category,dns_question_name,dns_resolvedip):
        self.hitindex = hitindex
        self.hitid = hitid
        self.process_parent_name = process_parent_name
        self.process_name = process_name
        self.process_args = process_args
        self.host_name = host_name
        self.user_name = user_name
        self.timestamp = timestamp
        self.time = time
        self.url_domain = url_domain
        self.url_path = url_path
        self.url_full = url_full
        self.source_ip = source_ip
        self.source_port = source_port
        self.source_user_name = source_user_name
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.rule_category = rule_category
        self.dns_question_name = dns_question_name
        self.dns_resolvedip = dns_resolvedip

class ElasticsearchAnalyzer(Analyzer):
    # Analyzer's constructor
    def __init__(self):
        # Call the constructor of the super class
        Analyzer.__init__(self)


        self.endpoints = self.get_param('config.endpoints', None, 'Elasticsearch endpoint is missing')
        self.kibana = self.get_param('config.kibana', None, None)
        self.index = self.get_param('config.index', None, 'Elasticsearch index is missing')
        self.keys = self.get_param('config.keys', None, None)
        self.users = self.get_param('config.users', None, None)
        self.passwords = self.get_param('config.passwords', None, None)
        self.dashboard = self.get_param('config.dashboard', None, None)
        self.verify = self.get_param('config.verifyssl', True, None)
        self.cert = self.get_param('config.cert_path', None, None)
        self.fields = self.get_param('config.field', None, 'Field is missing')
        self.data = self.get_param('data', None, 'Data is missing')
        self.size = self.get_param('config.size', None, 'size is missing')


    def summary(self, raw):
        taxonomies = []
        namespace = "ELK"
        predicate = "Hit(s)"

        value = "{}".format(raw['info']['hitcount'])
        if raw['info']['hitcount'] > 0:
            level = "suspicious"
        else:
            level = "safe"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        domains = []
        urls = []
        ips = []

        for hit in raw['hits']:
            #domains
            if 'url_domain' in hit:
                if isinstance(hit['url_domain'],list):
                    for domain in hit['url_domain']:
                        domains.append(domain)
                else:
                    domains.append(hit['url_domain'])
            if 'dns_question_name' in hit:
                if isinstance(hit['dns_question_name'],list):
                    for domain in hit['dns_question_name']:
                        domains.append(domain)
                else:
                    domains.append(hit['dns_question_name'])
            #urls
            if 'url_full' in hit:
                if isinstance(hit['url_full'],list):
                    for url in hit['url_full']:
                        urls.append(url)

            #ips
            if 'source_ip' in hit:
                if isinstance(hit['source_ip'],list):
                    for ip in hit['source_ip']:
                        ips.append(ip)
                else:
                    ips.append(hit['source_ip'])
            if 'destination_ip' in hit:
                if isinstance(hit['destination_ip'],list):
                    for ip in hit['destination_ip']:
                        ips.append(ip)
                else:
                    ips.append(hit['destination_ip'])
            if 'dns_resolvedip' in hit:
                if isinstance(hit['dns_resolvedip'],list):
                    for ip in hit['dns_resolvedip']:
                        ips.append(ip)
                else:
                    ips.append(hit['dns_resolvedip'])


        domains = list(set(domains))
        for domain in domains:
            if domain != "":
                observable = {'dataType' : 'domain', 'data' : domain, 'message' : 'domain from elastic'}
                artifacts.append(observable)
        urls = list(set(urls))
        for url in urls:
            if url != "":
                observable = {'dataType' : 'url', 'data' : url, 'message' : 'url from elastic'}
                artifacts.append(observable)
        ips = list(set(ips))
        for ip in ips:
            if ip != "":
                observable = {'dataType' : 'ip', 'data' : ip, 'message' : 'ip from elastic'}
                artifacts.append(observable)

        return artifacts

    def run(self):
        Analyzer.run(self)
        try:
            for endpoint,key,user,password in zip(self.endpoints,self.keys,self.users,self.passwords):
                if key:
                    es = Elasticsearch(
                        endpoint,
                        api_key = (key),
                        ca_certs=self.cert,
                        verify_certs=self.verify,
                        timeout=30
                    )
                elif user:
                    es = Elasticsearch(
                        endpoint,
                        http_auth = (user,password),
                        ca_certs=self.cert,
                        verify_certs=self.verify,
                        timeout=30
                    )
                else:
                    es = Elasticsearch(
                        endpoint,
                        ca_certs=self.cert,
                        verify_certs=self.verify,
                        timeout=30
                    )

                info = {}
                hits = []
                devices = []
                total = 'eq'
                #url that links to kibana dashboard
                info['query'] = ""
                #query string to show kql search
                info['querystring'] = ""
                self.fields = [x.lower() for x in self.fields]
                #remove all hash fields if not a hash
                if self.data_type != 'hash':
                    self.fields = list(filter( lambda s: not ("hash" in s), self.fields))
                #remove all ip fields if not an ip
                if self.data_type != 'ip':
                    self.fields = list(filter( lambda s: not ("ip" in s), self.fields))
                #remove all url and domain fields if not a url or domain or fqdn
                if self.data_type != 'domain' and self.data_type != 'url' and self.data_type != 'fqdn':
                    self.fields = list(filter( lambda s: not ("url" in s or "domain" in s), self.fields))
                if self.kibana and self.dashboard:
                    #building query
                    info['query'] += self.kibana+"/app/kibana#/dashboard/"+self.dashboard+\
                    "?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-1M,to:now))&_a=(columns:!(_source),interval:auto,query:(language:kuery,query:'"
                    #building query and query string
                    info['query'] += self.fields[0] + "%20:%20%22" + self.data
                    info['querystring'] = self.fields[0] + ':"' + self.data
                    for field in self.fields[1:]:
                        info['query'] += "%22%20or%20" + field + "%20:%20%22" + self.data
                        info['querystring'] += '" or ' + field + ':"' + self.data
                    info['query'] += "%22'),sort:!(!(start_time,desc)))"
                    info['querystring'] += '"'
                #loop to get hits from each index
                for index in self.index:
                    #search elastic for fields in each index
                    res = es.search(size=self.size,index=index,body={'sort':[{"@timestamp":{"order":"desc"}}],'query':{'multi_match':{'query':self.data, 'fields':self.fields}}})
                    #if relation is gte then more logs exist than we will display
                    if res['hits']['total']['relation'] == 'gte' or res['hits']['total']['relation'] == 'gt':
                        total = 'gte'
                    #adding results from each query
                    for hit in res['hits']['hits']:
                        hitindex = hit['_index']
                        hitid = hit['_id']
                        #process fields
                        process_parent_name = ""
                        process_name = ""
                        process_args = ""
                        #user fields
                        user_name = ""
                        #host fields
                        host_name = ""
                        #base fields
                        timestamp = ""
                        #destination fields
                        destination_ip = ""
                        destination_port = ""
                        #source fields
                        source_ip = ""
                        source_port = ""
                        source_user_name = ""
                        #event fields
                        event_action = ""
                        #url fields
                        url_domain = ""
                        url_path = ""
                        url_full = ""
                        #dns fields
                        dns_question_name = ""
                        dns_resolvedip = ""
                        #rule fields
                        rule_category = ""

                        #base fields
                        if '@timestamp' in hit['_source']:
                            if isinstance(hit['_source']['@timestamp'],str):
                                timestamp = dateutil.parser.parse(hit['_source']['@timestamp'])
                                time = timestamp.astimezone().strftime("%m/%d/%Y %I:%M %p")
                                timestamp = str(timestamp)
                            else:
                                timestamp = dateutil.parser.parse(datetime.fromtimestamp(float(hit['_source']['@timestamp']/1000)).strftime('%c'))
                                time = timestamp.astimezone().strftime("%m/%d/%Y %I:%M %p")
                                timestamp = str(timestamp)
                        #host fields
                        if 'host' in hit['_source']:
                            if 'name' in hit['_source']['host']:
                                host_name = hit['_source']['host']['name']
                        #process fields
                        if 'process' in hit['_source']:
                            if 'parent' in hit['_source']['process']:
                                if 'name' in hit['_source']['process']['parent']:
                                    process_parent_name = hit['_source']['process']['parent']['name']
                            if 'name' in hit['_source']['process']:
                                process_name = hit['_source']['process']['name']
                            if 'args' in hit['_source']['process']:
                                process_args = hit['_source']['process']['args']
                        #destination fields
                        if 'destination' in hit['_source']:
                            if 'ip' in hit['_source']['destination']:
                                destination_ip = hit['_source']['destination']['ip']
                            if 'port' in hit['_source']['destination']:
                                destination_port = hit['_source']['destination']['port']
                        #source fields
                        if 'source' in hit['_source']:
                            if 'ip' in hit['_source']['source']:
                                source_ip = hit['_source']['source']['ip']
                            if 'port' in hit['_source']['source']:
                                source_port = hit['_source']['source']['port']
                            if 'user' in hit['_source']['source']:
                                if 'name' in hit['_source']['source']['user']:
                                    source_user_name = hit['_source']['source']['user']['name']
                        #event fields
                        if 'event' in hit['_source']:
                            if 'action' in hit['_source']['event']:
                                event_action = hit['_source']['event']['action']
                        #url fields
                        if 'url' in hit['_source']:
                            if 'domain' in hit['_source']['url']:
                                url_domain = hit['_source']['url']['domain']
                            if 'path' in hit['_source']['url']:
                                url_path = hit['_source']['url']['path']
                            if 'full' in hit['_source']['url']:
                                url_full = hit['_source']['url']['full']
                        #user fields
                        if 'user' in hit['_source']:
                            if 'name' in hit['_source']['user']:
                                user_name = hit['_source']['user']['name']
                        #rule fields
                        if 'rule' in hit['_source']:
                            if 'category' in hit['_source']['rule']:
                                rule_category = hit['_source']['rule']['category']
                        #dns fields
                        if 'dns' in hit['_source']:
                            if 'question' in hit['_source']['dns']:
                                if 'name' in hit['_source']['dns']['question']:
                                    dns_question_name = hit['_source']['dns']['question']['name']
                            if 'resolved_ip' in hit['_source']['dns']:
                                dns_resolvedip = hit['_source']['dns']['resolved_ip']


                        hits.append(Hit(hitindex,hitid,process_parent_name,process_name,process_args,user_name,host_name,\
                        timestamp,time,destination_ip,destination_port,source_ip,source_port,source_user_name,\
                            url_domain,url_path,url_full,rule_category,dns_question_name,dns_resolvedip))

                #setup users
                usernames = [item.user_name for item in hits]
                source_usernames = [item.source_user_name for item in hits]
                usernames.extend(source_usernames)
                info['uniqueusers'] =  list(set(usernames))
                if "" in info['uniqueusers']:
                    info['uniqueusers'].remove("")
                info['userhitcount'] = len(info['uniqueusers'])

                #setup devices
                devices = [item.host_name for item in hits]
                info['uniquedevices'] =  list(set(devices))
                if "" in info['uniquedevices']:
                    info['uniquedevices'].remove("")
                info['devicehitcount'] = len(info['uniquedevices'])

                #observable that was searched on
                info['data'] = self.data
                info['dashboard'] = self.dashboard
                info['hitcount'] = len(hits)

                #sort the hits based on timestamp
                hits.sort(key=operator.attrgetter('timestamp'), reverse=True)
                hits = [ob.__dict__ for ob in hits]

                self.report({'hits' : hits,
                             'info' : info,
                             'total': total})

        except Exception as e:
            self.unexpectedError(e)
            return


if __name__ == '__main__':
    ElasticsearchAnalyzer().run()