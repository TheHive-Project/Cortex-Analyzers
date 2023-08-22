import json


class IlluminateServiceFile():
    """Base service class for all RiskIQ service files."""

    def __init__(self):
        self._name = ''
        self._version = '1.0'
        self._author = 'RiskIQ'
        self._url = 'https://github.com/TheHive-Project/Cortex-Analyzers'
        self._license = 'AGPL-V3'
        self._command = 'RiskIQ/_analyzer.py'
        self._baseconfig = 'RiskIQ'
        self._description = ''
        self._dataTypeList = ["domain","fqdn","ip"]
        self._taxonomy_namespace = 'RIQ'
        self._taxonomy_predicate = 'RiskIQ'
        self._taxonomy_valuekey = None
        self._config = {
            'property': None,
            'auto_extract': True
        }
        self._configitems = [
            {
                'name': 'username',
                'description': 'API username of the RiskIQ Illuminate or PassiveTotal account (usually an email address)',
                'type': 'string',
                'multi': False,
                'required': True
            },
            {
                'name': 'api_key',
                'description': 'API key of the RiskIQ Illuminate or PassiveTotal account',
                'type': 'string',
                'multi': False,
                'required': True
            },
            {
                'name': 'days_back',
                'description': 'Number of days back to search for date-bounded historical queries',
                'type': 'number',
                'multi': False,
                'required': False,
                'defaultValue': 180
            },
        ]
    
    def generate(self):
        """Creates and writes a JSON file to the local directory describing this service."""
        obj = {
            'name': self._name,
            'version': self._version,
            'author': self._author,
            'url': self._url,
            'license': self._license,
            'description': self._description,
            'dataTypeList': self._dataTypeList,
            'command': self._command,
            'baseConfig': self._baseconfig,
            'config': self._config,
            'configurationItems': self._configitems,
        }
        filename = '{}.json'.format(self._name)
        with open(filename, 'w') as f:
            json.dump(obj, f, indent=2, sort_keys=True)
    
    def get_taxonomies(self, data):
        """Get a list of taxonomies for this service."""
        try:
            level = self.get_taxonomy_level(data)
        except AttributeError:
            level = 'info'
        return [
            {
                'level': level,
                'namespace': self._taxonomy_namespace,
                'predicate': self._taxonomy_predicate,
                'value': data.get(self._taxonomy_valuekey, None),
            }
        ]

    def summarize(self, data):
        """Build summary data structure for data processed by this service."""
        return { 'taxonomies': self.get_taxonomies(data) }
    
    def transform(self, data):
        """Optionally post-process report data.
        
        Used by IlluminateAnalyzer.run() to give a service an opportunity to transform
        data before sending it upstream.
        """
        return data
    
    def build_artifacts(self, report):
        return None
    


class Reputation(IlluminateServiceFile):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_Reputation'
        self._description = 'RiskIQ Illuminate Reputation Score for an indicator.'
        self._taxonomy_predicate = 'ReputationScore'
        self._taxonomy_valuekey = 'score'
        self._config['property'] = 'reputation'
    
    
    def get_taxonomy_level(self, data):
        levels = {
            'SUSPICIOUS': 'suspicious',
            'MALICIOUS': 'malicious',
            'GOOD': 'info',
            'UNKOWN': 'info'
        }
        return levels.get(data['classification'],'info')
    
    def transform(self, data):
        classes = {
            'SUSPICIOUS': 'warning',
            'MALICIOUS': 'danger',
            'GOOD': 'success',
            'UNKOWN': 'info'
        }
        data['uicontext'] = classes.get(data['classification'],'info')
        for index, rule in enumerate(data['rules']):
            if rule['severity'] >= 4:
                uicontext = 'danger'
            elif rule['severity'] >= 2:
                uicontext = 'warning'
            else:
                uicontext = 'info'
            data['rules'][index]['uicontext'] = uicontext
        return data



class Summary(IlluminateServiceFile):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_Summary'
        self._description = 'RiskIQ Illuminate and PassiveTotal datasets with records for an indicator.'
        self._taxonomy_predicate = 'Summary'
        self._config['property'] = 'summary'
    
    def get_taxonomies(self, data):
        levels = {
            'malware_hashes': 'malicious',
            'articles': 'suspicious',
            'projects': 'suspicious'
        }
        taxonomies = []
        for dataset, count in data.items():
            if not type(count) is int:
                continue
            if dataset in levels.keys() and count > 0:
                level = levels[dataset]
            else:
                level = 'info'
            if dataset == 'total':
                continue
            if dataset == 'malware_hashes':
                dataset = 'malware'
            taxonomies.append({
                'level': level,
                'namespace': self._taxonomy_namespace,
                'predicate': dataset.title(),
                'value': count
            })
        return taxonomies
    
    def transform(self, data):
        levels = {
            'malware_hashes': 'danger',
            'projects': 'warning',
            'articles': 'danger'
        }
        uicontexts = {}
        for field in ['resolutions','certificates','malware_hashes','projects','articles',
                      'trackers','components','hostpairs','cookies','services']:
            uicontexts[field] = levels.get(field,'info')
        data['uicontexts'] = uicontexts
        return data



class Whois(IlluminateServiceFile):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_Whois'
        self._description = 'RiskIQ Whois lookup for an indicator.'
        self._taxonomy_predicate = 'Whois'
        self._config['property'] = 'whois'
    
    def get_taxonomies(self, data):
        taxonomies = []
        if 'age' in data:
            age = data['age']
            if age < 180:
                level = 'suspicious'
            taxonomies.append({
                'level': 'suspicious' if age < 180 else 'info',
                'namespace': self._taxonomy_namespace,
                'predicate': 'Whois Age (days)',
                'value': age
            })
        for email in data.get('emails',[]):
            taxonomies.append({
                'level': 'info',
                'namespace': self._taxonomy_namespace,
                'predicate': 'Whois Email',
                'value': email
            })
        return taxonomies



class SuspiciousCount:

    def get_taxonomy_level(self, data):
        return 'suspicious' if data.get('totalrecords',0) > 0 else 'info'



class Articles(IlluminateServiceFile, SuspiciousCount):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_Articles'
        self._description = 'RiskIQ: OSINT articles that reference an indicator.'
        self._taxonomy_predicate = 'Articles'
        self._taxonomy_valuekey = 'totalrecords'
        self._config['property'] = 'articles'
    


class Artifacts(IlluminateServiceFile, SuspiciousCount):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_Artifacts'
        self._description = 'RiskIQ: Illuminate / PassiveTotal project artifacts that match an indicator.'
        self._taxonomy_predicate = 'Artifacts'
        self._taxonomy_level = 'suspicious'
        self._taxonomy_valuekey = 'totalrecords'
        self._config['property'] = 'artifacts' 



class Certificates(IlluminateServiceFile):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_Certificates'
        self._description = 'RiskIQ: SSL/TLS certificates associated with an indicator.'
        self._taxonomy_predicate = 'Certificates'
        self._taxonomy_level = 'info'
        self._taxonomy_valuekey = 'totalrecords'
        self._config['property'] = 'certificates'



class Components(IlluminateServiceFile):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_Components'
        self._description = 'RiskIQ: web components observed during crawls on a hostname.'
        self._taxonomy_predicate = 'Components'
        self._taxonomy_level = 'info'
        self._taxonomy_valuekey = 'totalrecords'
        self._config['property'] = 'components'



class Cookies(IlluminateServiceFile):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_Cookies'
        self._description = 'RiskIQ: cookies observed during crawls on a hostname.'
        self._taxonomy_predicate = 'Cookies'
        self._taxonomy_level = 'info'
        self._taxonomy_valuekey = 'totalrecords'
        self._config['property'] = 'cookies'



class HostpairParents(IlluminateServiceFile):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_HostpairParents'
        self._description = 'RiskIQ: hosts with a parent web component relationship to an IOC.'
        self._taxonomy_predicate = 'HostpairParents'
        self._taxonomy_level = 'info'
        self._taxonomy_valuekey = 'totalrecords'
        self._config['property'] = 'hostpair_parents'



class HostpairChildren(IlluminateServiceFile):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_HostpairChildren'
        self._description = 'RiskIQ: hosts with a child web component relationship to an IOC.'
        self._taxonomy_predicate = 'HostpairChildren'
        self._taxonomy_level = 'info'
        self._taxonomy_valuekey = 'totalrecords'
        self._config['property'] = 'hostpair_children'



class Malware(IlluminateServiceFile):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_Malware'
        self._description = 'RiskIQ: malware hashes from various sources associated with an IOC.'
        self._taxonomy_predicate = 'Malware'
        self._taxonomy_level = 'malicious'
        self._taxonomy_valuekey = 'totalrecords'
        self._config['property'] = 'malware'



class Projects(IlluminateServiceFile):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_Projects'
        self._description = 'RiskIQ: Illuminate / PassiveTotal projects that contain an artifact which matches an IOC.'
        self._taxonomy_predicate = 'Projects'
        self._taxonomy_level = 'suspicious'
        self._taxonomy_valuekey = 'totalrecords'
        self._config['property'] = 'projects'



class Resolutions(IlluminateServiceFile):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_Resolutions'
        self._description = 'RiskIQ: PDNS resolutions for an IOC.'
        self._taxonomy_predicate = 'Resolutions'
        self._taxonomy_level = 'info'
        self._taxonomy_valuekey = 'totalrecords'
        self._config['property'] = 'resolutions'



class Subdomains(IlluminateServiceFile):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_Subdomains'
        self._description = 'RiskIQ: subdomains observed historically in pDNS records.'
        self._dataTypeList = ['fqdn','domain']
        self._taxonomy_predicate = 'Subdomains'
        self._taxonomy_level = 'info'
        self._taxonomy_valuekey = 'totalrecords'
        self._config['property'] = 'subdomains'
    
    def build_artifacts(self, report):
        return [ { 'dataType': 'fqdn', 'data': r.get('hostname') } for r in report.get('records', []) ]



class Trackers(IlluminateServiceFile):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_Trackers'
        self._description = 'RiskIQ: trackers observed during a crawl on a host.'
        self._taxonomy_predicate = 'Trackers'
        self._taxonomy_level = 'info'
        self._taxonomy_valuekey = 'totalrecords'
        self._config['property'] = 'trackers'



class Services(IlluminateServiceFile):
    
    def __init__(self):
        super().__init__()
        self._name = 'RiskIQ_Services'
        self._description = 'RiskIQ: services observed on an IP address.'
        self._dataTypeList = ['ip']
        self._taxonomy_predicate = 'Services'
        self._taxonomy_level = 'info'
        self._taxonomy_valuekey = 'totalrecords'
        self._config['property'] = 'services'



SERVICES = {
    'artifacts': Artifacts,
    'articles': Articles,
    'certificates': Certificates,
    'components': Components,
    'cookies': Cookies,
    'hostpair_parents': HostpairParents,
    'hostpair_children': HostpairChildren,
    'malware': Malware,
    'projects': Projects,
    'reputation': Reputation,
    'resolutions': Resolutions,
    'services': Services,
    'subdomains': Subdomains,
    'trackers': Trackers,
    'summary': Summary,
    'whois': Whois,
}


if __name__ == '__main__':
    import argparse
    import subprocess

    parser = argparse.ArgumentParser()
    cmdgroup = parser.add_mutually_exclusive_group()
    cmdgroup.add_argument('--generate', dest='cmd', action='store_const', const='generate',
                          help='Generate service files for each service.')
    cmdgroup.add_argument('--test', dest='cmd', action='store_const',const='test',
                          help='Test a service')
    parser.add_argument('--property', choices=SERVICES.keys(),
                        help='Analyzer object property to test.')
    parser.add_argument('--input',
                        help='Input value of the IOC to test.')
    parser.add_argument('--type', choices=['fqdn','domain','ip'],
                        help='TheHive type of the IOC to test.')
    parser.add_argument('--username',
                        help='API username; will be read from passivetotal lib if not provided')
    parser.add_argument('--apikey',
                        help='API key; will be read from passivetotal lib if not provided')
    parser.add_argument('--days-back', default=180, type=int,
                        help='Number of days back to search.')
    args = parser.parse_args()

    if args.cmd is None:
        parser.print_help()
        exit(1)

    if args.cmd == 'generate':
        if args.property is not None:
            SERVICES[args.property]().generate()
        else:
            for svc in SERVICES.values():
                svc().generate()
        exit(0)
    
    if args.cmd == 'test':
        if args.property is None:
            print('Property (--property) is required for a test')
            exit(1)
        if args.input is None:
            print('Input value (--input) is required for a test')
            exit(1)
        if args.type is None:
            print('Input type (--type) is required for a test')
        if args.username is None or args.apikey is None:
            from passivetotal.libs.account import AccountClient
            client = AccountClient.from_config()
        username = client.username if args.username is None else args.username
        apikey = client.api_key if args.apikey is None else args.apikey
        test = {
            "data": args.input,
            "dataType": args.type,
            "tlp":0,
            "config":{
                "key":"1234567890abcdef",
                "max_tlp":3,
                "check_tlp":True,
                "property":args.property,
                "days_back": args.days_back,
                "username": username,
                "api_key": apikey,
                "service": 'RiskIQ_{}'.format(args.property.title()),
            }
        }
        result = subprocess.run(
            ['python3','_analyzer.py'], 
            input=json.dumps(test),
            stdout=subprocess.PIPE,
            text=True
        )
        print(result.stdout)

    