"""FileInfo oletools submodule; WIP"""
from .submodule_base import SubmoduleBaseclass
from oletools.olevba import VBA_Parser_CLI
from oletools.msodde import process_file
from oletools.olevba import __version__ as olevba_version
from oletools.msodde import __version__ as msodde_version
from oletools.crypto import is_encrypted, decrypt


class OLEToolsSubmodule(SubmoduleBaseclass):
    """Try to inspect files using python oletools."""

    def __init__(self):
        SubmoduleBaseclass.__init__(self)
        self.name = 'Oletools Submodule'

    def check_file(self, **kwargs):
        """Oletools accepts MS office documents."""

        try:
            if kwargs.get('filetype') in [
                'DOC',
                'DOCM',
                'DOCX',
                'XLS',
                'XLSM',
                'XLSX',
                'PPT',
                'PPTM',
                'PPTX'
            ] or (kwargs.get('mimetype').startswith("application/vnd.openxmlformats-officedocument") or
                 kwargs.get('mimetype').startswith("application/encrypted") or
                 kwargs.get('mimetype').startswith("application/vnd.ms-") or
                 kwargs.get('mimetype').startswith("application/msword") or
                 kwargs.get('mimetype').startswith("Composite Document File V2 Document")
            ):
                if kwargs.get('mimetype').startswith("application/encrypted") and not is_encrypted(kwargs.get('file')):
                    return False
                return True
        except KeyError:
            return False
        return False

    def analyze_file(self, path):
        # Run the analyze functions
        self.encrypted = {'encrypted': is_encrypted(path)}
        if is_encrypted(path):
            import io, hashlib

            with io.open(path, 'rb') as fh:
                buf = fh.read()
                md5 = hashlib.md5()
                md5.update(buf)
                sha1 = hashlib.sha1()
                sha1.update(buf)
                sha256 = hashlib.sha256()
                sha256.update(buf)

            self.encrypted = {'encrypted': is_encrypted(path),
                             'sha256': sha256.hexdigest(),
                             'sha1': sha1.hexdigest(),
                             'md5': md5.hexdigest()}

        self.analyze_vba(path)
        self.analyze_dde(path)

        return self.results

    def module_summary(self):
        taxonomies = []
        level = 'info'
        namespace = 'FileInfo'
        predicate = ''
        value = ''

        for section in self.results:
            if section['submodule_section_header'] == 'Olevba':
                predicate = 'Olevba'
                if len(section['submodule_section_content']['macros']) > 0:
                    type_list = ['VBA']
                    add_VBA = True
                else:
                    type_list = []
                try:
                    for a in section['submodule_section_content']['analysis']:
                        if a["type"] not in type_list:
                            type_list.append(a["type"])
                except:
                    type_list.append("None")


                if "Suspicious" in type_list:
                    level = 'suspicious'
                if "VBA string" in type_list:
                    taxonomies.append(self.build_taxonomy(level, namespace, predicate, "VBA string"))
                    add_VBA = False
                if "Base64 String" in type_list:
                    taxonomies.append(self.build_taxonomy(level, namespace, predicate, "Base64 string"))
                    add_VBA = False
                if "Hex String" in type_list:
                    taxonomies.append(self.build_taxonomy(level, namespace, predicate, "Hex string"))
                    add_VBA = False
                if "VBA" in type_list and add_VBA:
                    taxonomies.append(self.build_taxonomy(level, namespace, predicate, "Macro found"))
                if "None" in type_list:
                    taxonomies.append(self.build_taxonomy("safe", namespace, predicate, "None"))

            if section['submodule_section_header'] == 'DDE Analysis':
                predicate = 'DDE'
                if section['submodule_section_content'].get('Info'):
                    level = 'safe'
                    taxonomies.append(self.build_taxonomy(level, namespace, predicate, 'None'))
                else:
                    level = 'suspicious'
                    taxonomies.append(self.build_taxonomy(level, namespace, predicate, 'URL found'))

        self.summary['taxonomies'] = taxonomies
        self.summary['Olevba'] = olevba_version
        self.summary['Msodde'] = msodde_version
        self.summary['encrypted_file'] = self.encrypted
        return self.summary

    def analyze_vba(self, path):
        """Analyze a given sample for malicious vba."""

        try:
            if is_encrypted(path):
                path = decrypt(path)
            vba_parser = VBA_Parser_CLI(path, relaxed=True)
            vbaparser_result = vba_parser.process_file_json(show_decoded_strings=True,
                                                            display_code=True,
                                                            hide_attributes=False,
                                                            vba_code_only=False,
                                                            show_deobfuscated_code=True,
                                                            deobfuscate=True)
            self.add_result_subsection('Olevba', vbaparser_result)
        except TypeError:
            self.add_result_subsection('Oletools VBA Analysis failed', 'Analysis failed due to an filetype error.'
                                                                       'The file does not seem to be a valid MS-Office '
                                                                       'file.')

    def analyze_dde(self, path):
        # version = {'Msodde version': msodde_version}
        results = process_file(path)
        if len(results) > 0:
            self.add_result_subsection('DDE Analysis', {'DDEUrl': results})
        else:
            self.add_result_subsection('DDE Analysis', {'Info': 'No DDE URLs found.'})


