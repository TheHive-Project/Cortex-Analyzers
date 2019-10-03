from pdfid.pdfid import *

import json

from .submodule_base import SubmoduleBaseclass


class PDFIDSubmodule(SubmoduleBaseclass):
    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = 'PDF Information'

    def check_file(self, **kwargs):
        """
        PDFiD submodule will analyze every PDF file and deliver useful information about its structure

        :return: True
        """
        if kwargs.get('filetype') in ['PDF']:
            return True

    def module_summary(self):
        taxonomies = []
        level = 'info'
        namespace = 'FileInfo'
        predicate = 'PDFiD'
        value = ''
        pdfid_version = ''
        for section in self.results:
            if section['submodule_section_header'] == 'PDFiD Information':
                for subsection in section['submodule_section_content']:
                    if subsection['pdfid']:
                        pdfid_version = subsection['pdfid']['version']
                        for keyword in subsection['pdfid']['keywords']['keyword']:
                            if keyword['name'] in ['/JS', '/JavaScript', '/OpenAction'] and keyword['count'] > 0:
                                level = 'suspicious'
                                taxonomies.append(self.build_taxonomy(level, namespace, predicate, keyword['name']))

        self.summary['taxonomies'] = taxonomies
        self.summary['pdfid'] = pdfid_version
        return self.summary

    def pdfid_cmd(self, path):
        try:
            j = json.loads(
                PDFiD2JSON(PDFiD(path, allNames=True, extraData=True, disarm=False, force=True), force=True))
        except Exception as e:
            return e
        return j


    def analyze_file(self, path):
        self.add_result_subsection('PDFiD Information', self.pdfid_cmd(path))
        return self.results
