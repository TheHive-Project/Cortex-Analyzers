#!/usr/bin/env python
import pyexifinfo


from cortexutils.analyzer import Analyzer
from submodules import *


class FileInfoAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.filepath = self.get_param('file', None, 'File parameter is missing.')
        self.filename = self.get_param('filename', None, 'Filename is missing.')
        self.filetype = pyexifinfo.fileType(self.filepath)
        #self.auto_extract = False

        # Create a dictionary of custom submodules
        self.available_submodules = [
            GZIPSubmodule()
        ]

    def run(self):
        results = []

        # Add metadata to result directly as it's mandatory
        m = MetadataSubmodule()
        results.append({
            'submodule_name': m.name,
            'results': m.analyze_file(self.filepath)
        })

        for module in self.available_submodules:
            if module.check_file(file=self.filepath, filetype=self.filetype):
                # temporary report
                results.append({
                    'submodule_name': module.name,
                    'results': module.analyze_file(self.filepath)
                })
        self.report(results)



if __name__ == '__main__':
    FileInfoAnalyzer().run()
