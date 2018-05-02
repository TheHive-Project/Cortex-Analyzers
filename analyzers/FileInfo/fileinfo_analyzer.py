#!/usr/bin/env python
import pyexifinfo

from cortexutils.analyzer import Analyzer
from submodules import available_submodules
from submodules.submodule_metadata import MetadataSubmodule


class FileInfoAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.filepath = self.get_param('file', None, 'File parameter is missing.')
        self.filename = self.get_param('filename', None, 'Filename is missing.')
        self.filetype = pyexifinfo.fileType(self.filepath)

    def run(self):
        results = []

        # Add metadata to result directly as it's mandatory
        m = MetadataSubmodule()
        results.append({
            'submodule_name': m.name,
            'results': m.analyze_file(self.filepath)
        })

        for module in available_submodules:
            if module.check_file(file=self.filepath, filetype=self.filetype, filename=self.filename):
                results.append({
                    'submodule_name': module.name,
                    'results': module.analyze_file(self.filepath)
                })
        self.report({'results': results})


if __name__ == '__main__':
    FileInfoAnalyzer().run()
