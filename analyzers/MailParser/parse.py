#!/usr/bin/env python
# encoding: utf-8

import sys
import json
import codecs
from lib.msgParser import Message
from cortexutils.analyzer import Analyzer
import sys
from pymisp import PyMISP

#fix to read mails in utf-8
reload(sys)
sys.setdefaultencoding('utf-8')


class MsgParserAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        self.filename = self.getParam('attachment.name', 'noname.ext')
        self.filepath = self.getParam('file', None, 'File is missing')
        self.cortexURL = self.getParam('config.cortexURL', None, 'Cortex URL is missing')
        self.fileInfo = self.getParam('config.fileInfo', None, 'File Info Analyzer is missing')
        self.MISPSearch = self.getParam('config.MISPSearch', None, 'MISP Analyzer is missing')

    def run(self):
        if self.data_type == 'file':
            try:
                self.report(Message(self.filepath).getReport(self.cortexURL, self.fileInfo, self.MISPSearch))
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()

if __name__ == '__main__':
    MsgParserAnalyzer().run()
