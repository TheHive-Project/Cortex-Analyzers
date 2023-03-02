import json
from passivetotal import ProjectsRequest, ArtifactsRequest

VERSION = '1.0'



class IlluminateServiceFile():
    """Base service class for all RiskIQ service files."""

    def __init__(self, **kwargs):
        self._name = 'RiskIQ_{}'.format(self.__class__.__name__)
        self._version = VERSION
        self._author = 'RiskIQ'
        self._url = 'https://github.com/TheHive-Project/Cortex-Analyzers'
        self._license = 'AGPL-V3'
        self._command = 'RiskIQ/_responder.py'
        self._baseconfig = 'RiskIQ'
        self._description = ''
        self._dataTypeList = []
        self._config = { 'service': self.__class__.__name__ }
        self._report = {}
        self._operations = []
        self._params = kwargs
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
                'name': 'project_visibility',
                'description': 'Visiblity for new RiskIQ Illuminate projects (analyst, team, or public).',
                'type': 'string',
                'multi': False,
                'required': True,
                'defaultValue': 'analyst'
            },
            {
                'name': 'project_prefix',
                'description': 'Prefix to add when auto-generating project names from case names.',
                'type': 'string',
                'multi': False,
                'required': False,
                'defaultValue': 'Hive:'
            },
            {
                'name': 'thehive_artifact_tag',
                'description': 'Tag to apply to artifact in TheHive when is has been pushed to a RiskIQ Illuminate Project (leave blank to skip tagging).',
                'type': 'string',
                'multi': False,
                'required': False
            },
            {
                'name': 'riq_artifact_tag',
                'description': 'Tag to apply to artifact in RiskIQ Illuminate when is has been pushed to an Illuminate Project (leave blank to skip tagging).',
                'type': 'string',
                'multi': False,
                'required': False
            }
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
    
    def add_operation(self, opname, **kwargs):
        self._operations.append({ 'name': opname, 'kwargs': kwargs})
    
    def run(self, input):
        return
    
    def get_report(self):
        return self._report

    def get_operations(self):
        return self._operations
    


class PushArtifactToProject(IlluminateServiceFile):

    CUSTOMFIELD = 'riq-project-guid'
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._description = 'Push a case to a RiskIQ Illuminate project.'
        self._dataTypeList = ["thehive:case_artifact"]
    
    def run(self, data):
        project_name = '{0}Case #{1} - {2}'.format(
            self._params.get('prefix',''), 
            data['case']['caseId'],
            data['case']['title']
        )
        self._report['case'] = data['case']
        project_description = data['case'].get('description','')
        project_visibility = self._params['visibility']
        request = ProjectsRequest(username=self._params['username'], api_key=self._params['api_key'])
        request.set_context('thehive','riq-responder',VERSION,self.__class__.__name__)
        projects = request.find_projects(project_name, visibility=project_visibility)
        if len(projects) > 1:
            self._report['error'] = 'Found more than one project with the same name'
            return
        if len(projects) == 0:
            project = request.create_project(project_name, visibility=project_visibility, description=project_description)
            self._report['riq_project'] = project
        else:
            project = projects[0]
        project_guid = project['guid']
        request = ArtifactsRequest(username=self._params['username'], api_key=self._params['api_key'])
        request.set_context('thehive','riq-responder',VERSION,self.__class__.__name__)
        artifact_tag = self._params.get('riq_artifact_tag')
        if artifact_tag is not None:
            tags = [artifact_tag]
        else:
            tags = None
        self._report['riq_artifact'] = request.upsert_artifact(project_guid, data['data'], tags=tags)
        thehive_artifact_tag = self._params.get('thehive_artifact_tag')
        if thehive_artifact_tag is not None:
            if thehive_artifact_tag not in data['tags']:
                self.add_operation('AddTagToArtifact', tag=thehive_artifact_tag)
        #self._report['ops'] = self._operations


    
    



SERVICES = {
    'PushArtifactToProject': PushArtifactToProject,
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
    parser.add_argument('--responder', choices=SERVICES.keys(),
                        help='Responder to test.')
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
        if args.responder is not None:
            SERVICES[args.responder]().generate()
        else:
            for svc in SERVICES.values():
                svc().generate()
        exit(0)
    
    if args.cmd == 'test':
        print('Sorry, testing responders is not yet implemented.')

    