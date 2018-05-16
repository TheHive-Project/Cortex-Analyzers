from pdfid.pdfid import *
import optparse
import json

from .submodule_base import SubmoduleBaseclass


class PDFIDSubmodule(SubmoduleBaseclass):
    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = 'PDF Information'

    def check_file(self, **kwargs):
        """
        PE submodule will analyze every PE like EXE, DLL or DRIVER, therefore it will always return true.

        :return: True
        """
        if kwargs.get('filetype') in ['PDF']:
            return True

    def pdfid_cmd(self, path):
        try:
            j = json.loads(
                PDFiD2JSON(PDFiD(path, allNames=True, extraData=True, disarm=True, force=True), force=True))
        except Exception as e:
            return e

    def analyze_file(self, path):
        self.add_result_subsection('PDFiD Information', self.pdfid_cmd(path))
        return self.results
