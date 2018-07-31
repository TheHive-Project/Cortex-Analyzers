#!/usr/bin/env python
# encoding: utf-8
import os
import sys
import codecs
import json


class Worker:

    def __init__(self):
        self.__set_encoding()

        # Prepare in/out/err streams
        self.fperror = sys.stderr
        self.fpinput = sys.stdin
        self.fpoutput = sys.stdout

        # Load input
        self._input = json.load(self.fpinput)

        # Set parameters
        self.data_type = self.get_param('dataType', None, 'Missing dataType field')
        self.tlp = self.get_param('tlp', 2)
        self.pap = self.get_param('pap', 2)

        self.enable_check_tlp = self.get_param('config.check_tlp', False)
        self.max_tlp = self.get_param('config.max_tlp', 2)

        self.enable_check_pap = self.get_param('config.check_pap', False)
        self.max_pap = self.get_param('config.max_pap', 2)

        # Set proxy configuration if available
        self.http_proxy = self.get_param('config.proxy.http')
        self.https_proxy = self.get_param('config.proxy.https')

        self.__set_proxies()

        # Finally run check tlp
        if not (self.__check_tlp()):
            self.error('TLP is higher than allowed.')

        if not (self.__check_pap()):
            self.error('PAP is higher than allowed.')

    def __set_proxies(self):
        if self.http_proxy is not None:
            os.environ['http_proxy'] = self.http_proxy
        if self.https_proxy is not None:
            os.environ['https_proxy'] = self.https_proxy

    @staticmethod
    def __set_encoding():
        try:
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
        except Exception:
            pass

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

    def __check_pap(self):
        """Check if pap is okay or not; returns False if too high."""

        return not (self.enable_check_pap and self.pap > self.max_pap)

    def get_data(self):
        """Wrapper for getting data from input dict.

        :return: Data (observable value) given through Cortex"""        
        return self.get_param('data', None, 'Missing data field')

    def get_param(self, name, default=None, message=None):
        """Just a wrapper for Analyzer.__get_param.
        :param name: Name of the parameter to get. JSON-like syntax, e.g. `config.username`
        :param default: Default value, if not found. Default: None
        :param message: Error message. If given and name not found, exit with error. Default: None"""

        return self.__get_param(self._input, name, default, message)

    def error(self, message, ensure_ascii=False):
        """Stop analyzer with an error message. Changing ensure_ascii can be helpful when stucking
        with ascii <-> utf-8 issues. Additionally, the input as returned, too. Maybe helpful when dealing with errors.
        :param message: Error message
        :param ensure_ascii: Force ascii output. Default: False"""

        analyzer_input = self._input
        if 'password' in analyzer_input.get('config', {}):
            analyzer_input['config']['password'] = 'REMOVED'
        if 'key' in analyzer_input.get('config', {}):
            analyzer_input['config']['key'] = 'REMOVED'
        if 'apikey' in analyzer_input.get('config', {}):
            analyzer_input['config']['apikey'] = 'REMOVED'
        if 'api_key' in analyzer_input.get('config', {}):
            analyzer_input['config']['api_key'] = 'REMOVED'

        json.dump({'success': False,
                   'input': analyzer_input,
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
