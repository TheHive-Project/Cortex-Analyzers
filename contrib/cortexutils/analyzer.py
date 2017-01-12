#!/usr/bin/env python
# encoding: utf-8

import os
import sys
import codecs
import json
import tempfile
import cStringIO
from iocp import Parser


class Analyzer:

    def __init__(self):
        self.setEncoding()

        self.errOutput = sys.stderr
        self.output = sys.stdout
        self.artifact = json.load(sys.stdin)
        self.tlp = self.getParam('tlp', 2)
        self.data_type = self.getParam(
            'dataType', None, 'Missing dataType field')
        self.check_tlp = self.getParam('config.check_tlp', False)
        self.max_tlp = self.getParam('config.max_tlp', 10)
        self.http_proxy = self.getParam('config.proxy.http')
        self.https_proxy = self.getParam('config.proxy.https')
        if self.http_proxy is not None:
            os.environ['http_proxy'] = self.http_proxy
        if self.https_proxy is not None:
            os.environ['https_proxy'] = self.https_proxy

    def getData(self):
        return self.getParam('data', None, 'Missing data field')

    def setEncoding(self):
        if sys.stdout.encoding != 'UTF-8':
            if sys.version_info.major == 3:
                sys.stdout = codecs.getwriter(
                    'utf-8')(sys.stdout.buffer, 'strict')
            else:
                sys.stdout = codecs.getwriter('utf-8')(sys.stdout, 'strict')
        if sys.stderr.encoding != 'UTF-8':
            if sys.version_info.major == 3:
                sys.stderr = codecs.getwriter(
                    'utf-8')(sys.stderr.buffer, 'strict')
            else:
                sys.stderr = codecs.getwriter('utf-8')(sys.stderr, 'strict')

    def getParam(self, name, default=None, message=None):
        return self.__getParam(self.artifact, name, default, message)

    def __getParam(self, current, name, default=None, message=None):
        if isinstance(name, str):
            name = name.split('.')
        if len(name) == 0:
            return current
        else:
            value = current.get(name[0])
            if value is None:
                if message is not None:
                    self.error(message)
                else:
                    return default
            else:
                return self.__getParam(value, name[1:], default, message)

    def _convertArtifactType(self, type):
        mapping = {'Host': 'domain'}
        try:
            return mapping[type]
        except:
            return type.lower()

    def summary(self, raw):
        return {}

    def artifacts(self, raw):
        try:
            stdout_ = sys.stdout
            stream = cStringIO.StringIO()
            sys.stdout = stream

            tmp = tempfile.NamedTemporaryFile(delete=False)
            try:
                tmp.write(json.dumps(raw))
                tmp.close()
                p = Parser.Parser(None, 'txt', True, None, 'json')
                p.parse(tmp.name)
            finally:
                os.remove(tmp.name)

            sys.stdout = stdout_

            parserOutput = stream.getvalue()
            parserOutput = filter(None, parserOutput.split('\n'))
            parserOutput = '[' + ','.join(parserOutput) + ']'
            iocs = json.loads(parserOutput)

            artifactList = []
            for ioc in iocs:
                i = {}
                i['type'] = self._convertArtifactType(ioc['type'])
                i['value'] = ioc['match']
                artifactList.append(i)

            return artifactList
        except:
            return []

    def error(self, message):
        json.dump({
            'success': False,
            'errorMessage': message
        }, self.output, ensure_ascii=False)
        sys.exit(1)

    def report(self, fullReport):
        summary = {}
        try:
            summary = self.summary(fullReport)
        except:
            summary = {}

        report = {
            'success': True,
            'summary': summary,
            'artifacts': self.artifacts(fullReport),
            'full': fullReport
        }
        json.dump(report, self.output, ensure_ascii=False)

    def notSupported(self):
        self.error('This datatype is not supported by this analyzer.')

    def unexpectedError(self, e):
        self.error('Unexpected Error: ' + str(e))

    def checkTlp(self, message):
        if self.check_tlp and (self.tlp > self.max_tlp):
            self.error(message)

    def run(self):
        self.checkTlp(
            'Error with TLP value ; see max_tlp in config or tlp value in input data')
