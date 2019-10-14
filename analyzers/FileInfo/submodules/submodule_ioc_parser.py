from iocp import Parser
import sys
from io import StringIO
from contextlib import redirect_stdout

import json

from .submodule_base import SubmoduleBaseclass


class IOCPSubmodule(SubmoduleBaseclass):
    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = 'IOC Parser'

    def check_file(self, **kwargs):
        """
        IOCP submodule will analyze every supported file and deliver IOCs found in it

        :return: True
        """
        if kwargs.get('filetype') in ['PDF']:
            return True

    def module_summary(self):
        taxonomies = []
        level = 'info'
        namespace = 'FileInfo'
        predicate = 'IOC Parser'
        value = ''
        for section in self.results:
            if section['submodule_section_header'] == 'IOC Parser Information':
                iocp_len = len(section.get('submodule_section_content').get('iocp_result')) 
                taxonomies.append(self.build_taxonomy(level, namespace, predicate, iocp_len))
        self.summary['taxonomies'] = taxonomies
        return self.summary

    def iocparser(self, path):
        """
        Use ioc_parser to extract IOCs


        :return: json 
        """
        out = StringIO()
        results = {'iocp_result': []}
        P = Parser
        oformat = 'json'
        try:
            with redirect_stdout(out):
                try:
                    P.Parser(output_format=oformat).parse(path)
                except TypeError:
                    pass
            oo = out.getvalue().split('\n')
            if oo[-1] == '':
                oo.pop()
            for i in oo:
                j = {}
                for k,v in json.loads(i).items():
                    if k in ['match','type']:
                        j.update({k:v})
                if j not in results['iocp_result']:
                    results['iocp_result'].append(j)
        except Exception as e:
            return e
        return results


    def analyze_file(self, path):
        self.add_result_subsection('IOC Parser Information', self.iocparser(path))
        return self.results
