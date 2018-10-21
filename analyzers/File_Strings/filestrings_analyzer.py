#!/usr/bin/env python
# encoding: utf-8

import sys
import string
import json
from cortexutils.analyzer import Analyzer
    
def strings(filename, min=5):
    with open(filename, "rb") as f:
        res = ""
        for c in f.read():
            if sys.version[0] == '2':
                if c in string.printable:
                    res += c
                    continue
                if len(res) >= min:
                    yield res
                res = ""
            else:
                if chr(c) in string.printable:
                    res += chr(c)
                    continue
                if len(res) >= min:
                    yield res
                res = ""
        if len(res) >= min: 
            yield res

class FileAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.filename = self.get_param('filename', 'noname.ext')
        self.filepath = self.get_param('file', None, 'File is missing')

    def file_strings(self, report):
        result  = report
        result['Strings'] = [] 
        try:
            for s in strings(self.filepath):
                result['Strings'].append(s)
        except Exception as excp:
            self.error(str(excp))
        return result

    def run(self):
        full_report = {}
        if self.data_type == 'file':
            try:
                self.file_strings(full_report)
                self.report(full_report)
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()

if __name__ == '__main__':
    FileAnalyzer().run()
