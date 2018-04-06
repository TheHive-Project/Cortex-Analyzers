import pefile
import pehashng

from .submodule_base import SubmoduleBaseclass


class PESubmodule(SubmoduleBaseclass):
    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = 'PE Information'

    def check_file(self, **kwargs):
        """
        PE submodule will analyze every PE like EXE, DLL or DRIVER, therefore it will always return true.

        :return: True
        """
        if kwargs.get('filetype') in ['Win32 EXE']:
            return True

    @staticmethod
    def pe_machine(pedict):
        if pedict:
            machinetype = pedict.get('FILE_HEADER').get('Machine').get('Value')
            mt = {'0x14c': 'x86', '0x0200': 'Itanium', '0x8664': 'x64'}
            if type(machinetype) is int:
                return mt[str(hex(machinetype))]
            else:
                return str(machinetype) + ' => Not x86/64 or Itanium'

    @staticmethod
    def compilation_timestamp(pedict):
        if pedict:
            return pedict.get('FILE_HEADER').get('TimeDateStamp').get('Value')
        else:
            return 'None'

    @staticmethod
    def pe_entrypoint(pedict):
        if pedict:
            return hex(pedict.get('OPTIONAL_HEADER').get('AddressOfEntryPoint').get('Value'))
        else:
            return 'None'

    def pe_info(self, pe):
        pedict = pe.dump_dict()
        table = []
        try:
            for fileinfo in pe.FileInfo:
                if fileinfo.Key.decode() == 'StringFileInfo':
                    for stringtable in fileinfo.StringTable:
                        for entry in stringtable.entries.items():
                            table.append({'Info': entry[0].decode(), 'Value': entry[1].decode()})

            table.append({'Info': 'Compilation Timestamp',
                          'Value': self.compilation_timestamp(pedict)})
            table.append({'Info': 'Target machine', 'Value': self.pe_machine(pedict)}),
            table.append({'Info': 'Entry Point', 'Value': self.pe_entrypoint(pedict)})
            return table
        except Exception as excp:
            return 'None'

    @staticmethod
    def pe_iat(pe):
        if pe:
            table = []
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imp = {'entryname': '', 'symbols': []}
                imp['entryname'] = entry.dll.decode()
                for symbol in entry.imports:
                    if symbol.name is not None:
                        imp['symbols'].append(symbol.name.decode())
                table.append(imp)
        return table

    # PE:Sections list of {Name, Size, Entropy, MD5, SHA1, SHA256, SHA512} #
    @staticmethod
    def pe_sections(pe):
        if pe:
            table = []
            for entry in pe.sections:
                sect = {'entryname': str(entry.Name.decode()), 'SizeOfRawData': hex(entry.SizeOfRawData),
                        'Entropy': entry.get_entropy(),
                        'MD5': entry.get_hash_md5(),
                        'SHA1': entry.get_hash_sha1(),
                        'SHA256': entry.get_hash_sha256(),
                        'SHA512': entry.get_hash_sha512()}
                table.append(sect)
                sect = {}
        return table

    def analyze_file(self, path):
        try:
            pe = pefile.PE(path)
            pedict = pe.dump_dict()
        except Exception as excp:
            print("Failed processing {}".format(path))

        self.add_result_subsection('Headers', self.pe_info(pe))
        self.add_result_subsection('Hashes', {
                'impash': pe.get_imphash(),
                'pehash': pehashng.pehashng(pe)
            })
        self.add_result_subsection('Import Adress Tables', self.pe_iat(pe))
        self.add_result_subsection('Sections', self.pe_sections(pe))
        return self.results
