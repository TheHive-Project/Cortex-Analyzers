#!/usr/bin/env python
import pyexifinfo
import magic

from cortexutils.analyzer import Analyzer
from submodules import available_submodules
from submodules.submodule_metadata import MetadataSubmodule


class FileInfoAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.filepath = self.get_param('file', None, 'File parameter is missing.')
        self.filename = self.get_param('filename', None, 'Filename is missing.')
        self.filetype = pyexifinfo.fileType(self.filepath)
        self.mimetype = magic.Magic(mime=True).from_file(self.filepath)


    def build_summary(self, module_results):

        summary = []
        for m in module_results:
            if m["submodule_section_summary"]["taxonomies"] != []:

                summary += m["submodule_section_summary"]["taxonomies"]

        return summary

    def run(self):
        results = []
        summary = []

        # Add metadata to result directly as it's mandatory
        m = MetadataSubmodule()
        matadata_results = m.analyze_file(self.filepath)
        results.append({
            'submodule_name': m.name,
            'results': matadata_results,
            'summary': self.build_summary(matadata_results)

        })
        # self.build_summary(summary, matadata_results)

        for module in available_submodules:
            if module.check_file(file=self.filepath, filetype=self.filetype, filename=self.filename,
                                 mimetype=self.mimetype):
                module_results = module.analyze_file(self.filepath)
                results.append({
                   'submodule_name': module.name,
                   'results': module_results,
                    'summary': self.build_summary(module_results)
                })

                # self.build_summary(summary, module_results)

        self.report({'results': results, 'summary': summary})


if __name__ == '__main__':
    FileInfoAnalyzer().run()
