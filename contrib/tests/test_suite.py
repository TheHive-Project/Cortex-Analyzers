#!/usr/bin/env python
# coding: utf-8

import os
import sys
import json
import unittest

from io import open
from cortexutils.analyzer import Analyzer

# Different lib when using python3 or 2
if sys.version_info >= (3, 0):
    from io import StringIO
else:
    from StringIO import StringIO


def load_test_fixture(fixture_path):
    path = os.path.dirname(os.path.abspath(__file__))
    fixture_file = open(path + '/' + fixture_path)
    input = fixture_file.read()
    fixture_file.close()
    sys.stdin = StringIO(input)
    sys.stdout = StringIO()


class TestMinimalConfig(unittest.TestCase):

    def setUp(self):
        load_test_fixture('fixtures/test-minimal-config.json')
        self.analyzer = Analyzer()

    def test_default_config(self):
        self.assertEqual(self.analyzer.data_type, 'ip')
        self.assertEqual(self.analyzer.tlp, 2)
        self.assertEqual(self.analyzer.enable_check_tlp, False)
        self.assertEqual(self.analyzer.max_tlp, 2)
        self.assertEqual(self.analyzer.http_proxy, None)
        self.assertEqual(self.analyzer.https_proxy, None)

    def test_artifact_data(self):
        self.assertEqual(self.analyzer.getData(), "1.1.1.1")
        self.assertEqual(self.analyzer.get_data(), "1.1.1.1")

    def test_params_data(self):
        self.assertEqual(self.analyzer.getParam('data'), "1.1.1.1")
        self.assertEqual(self.analyzer.get_param('data'), "1.1.1.1")


class TestProxyConfig(unittest.TestCase):

    def setUp(self):
        load_test_fixture('fixtures/test-proxy-config.json')
        self.analyzer = Analyzer()

    def test_proxy_config(self):
        proxy_url = 'http://local.proxy:8080'

        self.assertEqual(self.analyzer.http_proxy, proxy_url)
        self.assertEqual(self.analyzer.https_proxy, proxy_url)

        self.assertEqual(os.environ['http_proxy'], proxy_url)
        self.assertEqual(os.environ['https_proxy'], proxy_url)


class TestTlpConfig(unittest.TestCase):

    def setUp(self):
        load_test_fixture('fixtures/test-tlp-config.json')
        self.analyzer = Analyzer()

    def test_check_tlp_disabled(self):
        self.analyzer.enable_check_tlp = False

        # Using the _Analyzer__check_tlp notation to access managed method
        # __check_tlp
        self.assertEqual(self.analyzer._Analyzer__check_tlp(), True)

    def test_check_tlp_ko(self):
        self.analyzer.enable_check_tlp = True
        self.analyzer.max_tlp = 1
        self.analyzer.tlp = 3

        # Using the _Analyzer__check_tlp notation to access managed method
        # __check_tlp
        self.assertEqual(self.analyzer._Analyzer__check_tlp(), False)

    def test_check_tlp_ok(self):
        self.analyzer.enable_check_tlp = True
        self.analyzer.max_tlp = 3
        self.analyzer.tlp = 3

        # Using the _Analyzer__check_tlp notation to access managed method
        # __check_tlp
        self.assertEqual(self.analyzer._Analyzer__check_tlp(), True)


class TestErrorResponse(unittest.TestCase):

    def setUp(self):
        load_test_fixture('fixtures/test-error-response.json')
        self.analyzer = Analyzer()

    def test_error_response(self):
        self.assertEqual(self.analyzer.get_param('config.password'), "secret")
        self.assertEqual(self.analyzer.get_param('config.key'), "secret")
        self.assertEqual(self.analyzer.get_param('config.apikey'), "secret")
        self.assertEqual(self.analyzer.get_param('config.api_key'), "secret")

        # Run the error method
        with self.assertRaises(SystemExit):
            self.analyzer.error('Error', True)

        # Get the output
        output = self.analyzer.fpoutput.getvalue().strip()
        json_output = json.loads(output)

        self.assertEqual(json_output['success'], False)
        self.assertEqual(json_output['errorMessage'], 'Error')
        self.assertEqual(json_output['input']['dataType'], 'ip')
        self.assertEqual(json_output['input']['data'], '1.1.1.1')
        self.assertEqual(json_output['input']['config']['password'], 'REMOVED')
        self.assertEqual(json_output['input']['config']['key'], 'REMOVED')
        self.assertEqual(json_output['input']['config']['apikey'], 'REMOVED')
        self.assertEqual(json_output['input']['config']['api_key'], 'REMOVED')


class TestReportResponse(unittest.TestCase):

    def setUp(self):
        load_test_fixture('fixtures/test-report-response.json')
        self.analyzer = Analyzer()

    def test_error_response(self):
        # Run the analyzer report method
        self.analyzer.report({'report_id':'12345'})

        # Get the output
        output = self.analyzer.fpoutput.getvalue().strip()
        json_output = json.loads(output)

        self.assertEqual(json_output.get('success'), True)
        self.assertEqual(json_output.get('errorMessage', None), None)
        self.assertEqual(json_output['full']['report_id'], '12345')        

if __name__ == '__main__':
    unittest.main()
