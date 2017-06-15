#!/usr/bin/env python
# encoding: utf-8

import os
import sys
import codecs
import json
from cortexutils.extractor import Extractor


class Analyzer:

    def __init__(self):
        self.__set_encoding()

        # Prepare in/out/err streams
        self.fperror = sys.stderr
        self.fpinput = sys.stdin
        self.fpoutput = sys.stdout

        # Load input
        self.__input = json.load(self.fpinput)

        # Set parameters
        self.data_type = self.get_param('dataType', None, 'Missing dataType field')
        self.tlp = self.get_param('tlp', 2)

        self.enable_check_tlp = self.get_param('config.check_tlp', False)
        self.max_tlp = self.get_param('config.max_tlp', 2)

        # Set proxy configuration if available
        self.http_proxy = self.get_param('config.proxy.http')
        self.https_proxy = self.get_param('config.proxy.https')

        self.__set_proxies()

        # Finally run check tlp
        if not (self.__check_tlp()):
            self.error('TLP is higher than allowed.')

        # Not breaking compatibility
        self.artifact = self.__input

        # Check for auto extraction config
        self.auto_extract = self.get_param('config.auto_extract', True)

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

    def __set_proxies(self):
        if self.http_proxy is not None:
            os.environ['http_proxy'] = self.http_proxy
        if self.https_proxy is not None:
            os.environ['https_proxy'] = self.https_proxy

    def __set_encoding(self):
        if sys.stdout.encoding != 'UTF-8':
            if sys.version_info[0] == 3:
                sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
            else:
                sys.stdout = codecs.getwriter('utf-8')(sys.stdout, 'strict')
        if sys.stderr.encoding != 'UTF-8':
            if sys.version_info[0] == 3:
                sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
            else:
                sys.stderr = codecs.getwriter('utf-8')(sys.stderr, 'strict')

    def __get_param(self, source, name, default=None, message=None):
        """Extract a specific parameter from given source.
        :param source: Python dict to search through
        :param name: Name of the parameter to get. JSON-like syntax, e.g. `config.username` at first, but in recursive
                     calls a list
        :param default: Default value, if not found. Default: None
        :param message: Error message. If given and name not found, exit with error. Default: None"""

        if isinstance(name, str):
            name = name.split('.')

        if len(name) == 0:
            # The name is empty, return the source content
            return source
        else:
            new_source = source.get(name[0])
            if new_source is not None:
                return self.__get_param(new_source, name[1:], default, message)
            else:
                if message is not None:
                    self.error(message)
                return default

    def __check_tlp(self):
        """Check if tlp is okay or not; returns False if too high."""

        return not (self.enable_check_tlp and self.tlp > self.max_tlp)

    def get_data(self):
        """Wrapper for getting data from input dict.

        :return: Data (observable value) given through Cortex"""
        return self.get_param('data', None, 'Missing data field')


    def get_param(self, name, default=None, message=None):
        """Just a wrapper for Analyzer.__get_param.
        :param name: Name of the parameter to get. JSON-like syntax, e.g. `config.username`
        :param default: Default value, if not found. Default: None
        :param message: Error message. If given and name not found, exit with error. Default: None"""

        return self.__get_param(self.__input, name, default, message)

    def summary(self, raw):
        """Returns a summary, needed for 'short.html' template. Overwrite it for your needs!

        :returns: by default return an empty dict"""
        return {}

    def artifacts(self, raw):
        # Use the regex extractor, if auto_extract setting is not False
        if self.auto_extract:
            extractor = Extractor()
            return extractor.check_iterable(raw)

        # Return empty list
        return []

    def error(self, message, ensure_ascii=False):
        """Stop analyzer with an error message. Changing ensure_ascii can be helpful when stucking
        with ascii <-> utf-8 issues. Additionally, the input as returned, too. Maybe helpful when dealing with errors.
        :param message: Error message
        :param ensure_ascii: Force ascii output. Default: False"""

        analyzerInput = self.__input
        if 'password' in analyzerInput.get('config', {}):
            analyzerInput['config']['password'] = 'REMOVED'
        if 'key' in analyzerInput.get('config', {}):
            analyzerInput['config']['key'] = 'REMOVED'
        if 'apikey' in analyzerInput.get('config', {}):
            analyzerInput['config']['apikey'] = 'REMOVED'
        if 'api_key' in analyzerInput.get('config', {}):
            analyzerInput['config']['api_key'] = 'REMOVED'

        json.dump({'success': False,
                   'input': analyzerInput,
                   'errorMessage': message},
                  self.fpoutput,
                  ensure_ascii=ensure_ascii)

        # Force exit after error
        sys.exit(1)

    def report(self, full_report, ensure_ascii=False):
        """Returns a json dict via stdout.

        :param full_report: Analyzer results as dict.
        :param ensure_ascii: Force ascii output. Default: False"""

        summary = {}
        try:
            summary = self.summary(full_report)
        except:
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
