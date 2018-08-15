#!/usr/bin/env python
# encoding: utf-8

import json
from cortexutils.worker import Worker
from cortexutils.extractor import Extractor


class Analyzer(Worker):

    def __init__(self):
        Worker.__init__(self)

        # Not breaking compatibility
        self.artifact = self._input

        # Check for auto extraction config
        self.auto_extract = self.get_param('config.auto_extract', self.get_param('config.auto_extract_artifacts', True))

    def get_data(self):
        """Wrapper for getting data from input dict.

        :return: Data (observable value) given through Cortex"""
        if self.data_type == 'file':
            return self.get_param('filename', None, 'Missing filename.')
        return self.get_param('data', None, 'Missing data field')

    def build_taxonomy(self, level, namespace, predicate, value):
        """
        :param level: info, safe, suspicious or malicious
        :param namespace: Name of analyzer
        :param predicate: Name of service
        :param value: value
        :return: dict
        """
        # Set info level if something not expected is set
        if level not in ['info', 'safe', 'suspicious', 'malicious']:
            level = 'info'
        return {
                'level': level,
                'namespace': namespace,
                'predicate': predicate,
                'value': value
                }    

    def summary(self, raw):
        """Returns a summary, needed for 'short.html' template. Overwrite it for your needs!

        :returns: by default return an empty dict"""
        return {}

    def artifacts(self, raw):
        # Use the regex extractor, if auto_extract setting is not False
        if self.auto_extract:
            extractor = Extractor(ignore=self.get_data())
            return extractor.check_iterable(raw)

        # Return empty list
        return []

    def report(self, full_report, ensure_ascii=False):
        """Returns a json dict via stdout.

        :param full_report: Analyzer results as dict.
        :param ensure_ascii: Force ascii output. Default: False"""

        summary = {}
        try:
            summary = self.summary(full_report)
        except Exception:
            pass

        report = {
            'success': True,
            'summary': summary,
            'artifacts': self.artifacts(full_report),
            'full': full_report
        }
        json.dump(report, self.fpoutput, ensure_ascii=ensure_ascii)

    def run(self):
        """Overwritten by analyzers"""
        pass

    # Not breaking compatibility
    def notSupported(self):
        self.error('This datatype is not supported by this analyzer.')

    # Not breaking compatibility
    def unexpectedError(self, e):
        self.error('Unexpected Error: ' + str(e))

    # Not breaking compatibility
    def getData(self):
        """For not breaking compatibility to cortexutils.analyzer, this wraps get_data()"""
        return self.get_data()

    # Not breaking compatibility
    def getParam(self, name, default=None, message=None):
        """For not breaking compatibility to cortexutils.analyzer, this wraps get_param()"""
        return self.get_param(name=name, default=default, message=message)

    # Not breaking compatibility
    def checkTlp(self, message):
        if not (self.__check_tlp()):
            self.error(message)