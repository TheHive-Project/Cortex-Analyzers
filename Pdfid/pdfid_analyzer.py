#!/usr/bin/env python
# encoding: utf-8

import sys
import json
import codecs
from lib.pdfid import *
from cortexutils.analyzer import Analyzer


class PdfidAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.filename = self.getParam('attachment.name', 'noname.ext')
        self.filepath = self.getParam('file', None, 'File is missing')

    def summary(self, fullReport):
        result = {}
        detections = {}

        # Parse detections
        keywords = fullReport[0]['pdfid']['keywords']['keyword']
        for obj in keywords:
            if obj['name'].startswith('/'):
                detections[obj['name']] = obj['count']

        # Count detections
        countJavaScript = detections['/JavaScript']
        countOpenAction = detections['/OpenAction']
        countRichMedia = detections['/RichMedia']
        countObjStm = detections['/ObjStm']
        countOpenAction = detections['/OpenAction']
        countLaunch = detections['/Launch']

        score = countJavaScript + countOpenAction + countRichMedia + countObjStm + countOpenAction + countLaunch
        result.update({'score': score})

        if score > 0:
            result.update({'suspicious': True})
        else:
            result.update({'suspicious': False})

        result.update({'detections': detections})

        return result

    def run(self):
        if self.data_type == 'file':
            try:
                oParser = optparse.OptionParser(usage='usage: %prog [options] [pdf-file|zip-file|url|@file] ...\n')
                oParser.add_option('-s', '--scan', action='store_true', default=False, help='scan the given directory')
                oParser.add_option('-a', '--all', action='store_true', default=False, help='display all the names')
                oParser.add_option('-e', '--extra', action='store_true', default=False, help='display extra data, like dates')
                oParser.add_option('-f', '--force', action='store_true', default=False, help='force the scan of the file, even without proper %PDF header')
                oParser.add_option('-d', '--disarm', action='store_true', default=False, help='disable JavaScript and auto launch')
                oParser.add_option('-p', '--plugins', type=str, default='', help='plugins to load (separate plugins with a comma , ; @file supported)')
                oParser.add_option('-c', '--csv', action='store_true', default=False, help='output csv data when using plugins')
                oParser.add_option('-m', '--minimumscore', type=float, default=0.0, help='minimum score for plugin results output')
                oParser.add_option('-v', '--verbose', action='store_true', default=False, help='verbose (will also raise catched exceptions)')
                oParser.add_option('-S', '--select', type=str, default='', help='selection expression')
                oParser.add_option('-o', '--output', type=str, default='', help='output to log file')
                (options, args) = oParser.parse_args()

                result = PDFiD2JSON(PDFiD(self.filepath, options.all, options.extra, options.disarm, options.force), options.force)

                jsonResult = json.loads(result)
                jsonResult[0]['pdfid']['filename'] = self.filename

                self.report(jsonResult)
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    PdfidAnalyzer().run()
