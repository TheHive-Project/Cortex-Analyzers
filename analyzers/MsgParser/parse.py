#!/usr/bin/env python3
# encoding: utf-8

from lib.msgParser import Message
from cortexutils.analyzer import Analyzer


class MsgParserAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        self.filename = self.get_param('filename', 'noname.ext')
        self.filepath = self.get_param('file', None, 'File is missing')

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "MsgParser"
        predicate = "Attachments"
        value = "0"

        if "attachments" in raw:
            value = len(raw["attachments"])
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'file':
            try:
                self.report(Message(self.filepath).getReport())
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    MsgParserAnalyzer().run()
