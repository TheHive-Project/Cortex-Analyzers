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

    def summary(self, raw):
        taxonomies = []
        for submodule in raw['results']:
            taxonomies += submodule['summary']['taxonomies']
        return {'taxonomies': taxonomies}



    def run(self):
        results = []

        # Add metadata to result directly as it's mandatory
        m = MetadataSubmodule()
        metadata_results = m.analyze_file(self.filepath)
        results.append({
            'submodule_name': m.name,
            'results': metadata_results,
            'summary': m.module_summary()
        })

        for module in available_submodules:
            if module.check_file(file=self.filepath, filetype=self.filetype, filename=self.filename,
                                 mimetype=self.mimetype):
                module_results = module.analyze_file(self.filepath)
                module_summaries = module.module_summary()
                results.append({
                   'submodule_name': module.name,
                   'results': module_results,
                    'summary': module_summaries
                })

        self.report({'results': results})


if __name__ == '__main__':
    FileInfoAnalyzer().run()
