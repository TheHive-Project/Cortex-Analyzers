#!/usr/bin/python
# encoding: utf-8

# using https://bitbucket.org/decalage/oletools/wiki/olevba


import sys
import re
import os
import json
import codecs
from StringIO import StringIO
from cortexutils.analyzer import Analyzer


class OlevbaAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        self.filename = self.getParam('attachment.name', 'noname.ext')
        self.filepath = self.getParam('file', None, 'File is missing')

    def run(self):
        try:
            __import__('imp').find_module('oletools')
            from oletools.olevba import VBA_Parser, VBA_Scanner
            from oletools.olevba import __version__ as olevbaVersion
        except ImportError:
            self.error('Import Error: Module oletools not found')

        # Redirect stderr to devnull in case input file is not a valid office document. When parsing a non valid
        # document VBA Parser raises an error to stderr.
        redir_err = sys.stderr = StringIO()

        try:
            vba = VBA_Parser(self.filepath)
            result = {
                'Suspicious': False,
                'Base64 Strings': False,
                'Hex Strings': False,
                'Version': olevbaVersion
            }
        except TypeError:
            self.error('File type error: ' + redir_err.getvalue())

        # set stderr back to original __stderr__
        sys.stderr = sys.__stderr__

        if vba.detect_vba_macros():
            result['vba'] = 'VBA Macros found'
            streams = []
            for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                vba_scanner = VBA_Scanner(vba_code)
                scan_results = vba_scanner.scan(include_decoded_strings=False)
                vba_scan_results = []
                for kw_type, keyword, description in scan_results:
                    vba_scan_results.append({
                        'type': kw_type,
                        'keyword': keyword,
                        'description': description
                    })

                    if (kw_type == 'Suspicious'):
                        result['Suspicious'] = True
                    if (keyword == 'Base64 Strings'):
                        result['Base64 Strings'] = True
                    if (keyword == 'Hex Strings'):
                        result['Hex Strings'] = True

                streams.append({
                    'Filename': self.filename,
                    'OLE stream': stream_path,
                    'VBA filename': vba_filename,
                    'VBA code': vba_code,
                    'scan_result': vba_scan_results
                })
            result['streams'] = streams
        else:
            result['vba'] = 'No VBA Macros found'

        self.report(result)


if __name__ == '__main__':
    OlevbaAnalyzer().run()
