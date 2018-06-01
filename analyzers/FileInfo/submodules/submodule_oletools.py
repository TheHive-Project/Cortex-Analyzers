"""FileInfo oletools submodule; WIP"""
from .submodule_base import SubmoduleBaseclass
from oletools.olevba3 import VBA_Parser_CLI
from oletools.msodde import process_file


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
            ]:
                return True
        except KeyError:
            return False
        return False

    def analyze_file(self, path):
        # Run the analyze functions
        self.analyze_vba(path)
        self.analyze_dde(path)

        return self.results



    def olevba_summary(self, analysis):
        """ Build summary for Olevba part of the submodule"""

        summary = {'taxonomies': []}


        type_list = []
        for a in analysis:
            if a["type"] not in type_list:
                type_list.append(a["type"])

        predicate = "Olevba"
        namespace = "FileInfo"
        level = "info"

        if "Suspicious" in type_list:
            level = 'suspicious'
        if "VBA string" in type_list:
            summary["taxonomies"].append(self.build_taxonomy(level, namespace, predicate, "VBA string"))
        if "Base64 String" in type_list:
            summary["taxonomies"].append(self.build_taxonomy(level, namespace, predicate, "Base64 string"))
        if "Hex String" in type_list:
            summary["taxonomies"].append(self.build_taxonomy(level, namespace, predicate, "Hex string"))

        return summary

    def analyze_vba(self, path):
        """Analyze a given sample for malicious vba."""
        try:

            vba_parser = VBA_Parser_CLI(path, relaxed=True)
            vbaparser_result = vba_parser.process_file_json(show_decoded_strings=True,
                                                            display_code=True,
                                                            hide_attributes=False,
                                                            vba_code_only=False,
                                                            show_deobfuscated_code=True,
                                                            deobfuscate=True)
            self.add_result_subsection('Olevba', vbaparser_result, self.olevba_summary(vbaparser_result["analysis"]))
        except TypeError:
            self.add_result_subsection('Oletools VBA Analysis failed', 'Analysis failed due to an filetype error.'
                                                                       'The file does not seem to be a valid MS-Office '
                                                                       'file.')

    def analyze_dde(self, path):
        results = process_file(path)
        if len(results) > 0:
            self.add_result_subsection('Oletools DDE Analysis', {'DDEUrl': results}, {"DDE": True})
        else:
            self.add_result_subsection('Oletools DDE Analysis', {'Info': 'No DDE URLs found.'})


