import magic
import hashlib
import io
import pyexifinfo
import pefile

from .submodule_base import SubmoduleBaseclass
from ssdeep import Hash


class PESubmodule(SubmoduleBaseclass):
    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = 'PE'

    def check_file(self, **kwargs):
        """
        PE submodule will analyze every PE like EXE, DLL or DRIVER, therefore it will always return true.

        :return: True
        """
        if kwargs.get('filetype') in ['Win32 EXE']:
            return True

    def PE_info(self, pe):
        table = []
        try:
            for fileinfo in pe.FileInfo:
                if fileinfo.Key.decode() == 'StringFileInfo':
                    for stringtable in fileinfo.StringTable:
                        for entry in stringtable.entries.items():
                            table.append({'Info': entry[0].decode(), 'Value': entry[1].decode()})
            return table
        except Exception as excp:
            return 'None'

    def analyze_file(self, path):
        try:
            pe = pefile.PE(path)
            pedict = pe.dump_dict()
        except Exception as excp:
            print("Failed processing {}".format(path))

        self.add_result_subsection('PE Info', {
            "Info": self.PE_info(pe)
        })

        return self.results