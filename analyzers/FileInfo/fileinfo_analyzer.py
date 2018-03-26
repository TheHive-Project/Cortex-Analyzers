#!/usr/bin/env python

from cortexutils.analyzer import Analyzer
from submodules import *


class FileInfoAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.filepath = self.get_param('file', None, 'File parameter is missing.')
        self.filename = self.get_param('filename', None, 'Filename is missing.')

        # Create a dictionary of submodules
        self.available_submodules = [
            MetadataSubmodule()
        ]

    def run(self):

        for module in self.available_submodules:
            if module.check_file(self.filepath):
                # temporary report
                self.report(module.analyze_file(self.filepath))



if __name__ == '__main__':
    FileInfoAnalyzer().run()
