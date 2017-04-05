#!/usr/bin/env python
# coding: utf-8
from __future__ import unicode_literals

import os
import sys
import unittest
from io import StringIO
from io import open

from cortexutils.analyzer import Analyzer


def load_test_fixture(fixture_path):
    path = os.path.dirname(os.path.abspath(__file__))
    fixture_file = open(path + '/' + fixture_path, 'r', encoding="utf-8")
    input = fixture_file.read()
    fixture_file.close()
    sys.stdin = StringIO(input)


class TestMinimalConfig(unittest.TestCase):

    def setUp(self):
        load_test_fixture('test-minimal-config.json')
        self.analyzer = Analyzer()

    def test_default_config(self):
        self.assertEqual(self.analyzer.data_type, 'ip')
        self.assertEqual(self.analyzer.tlp, 2)
        self.assertEqual(self.analyzer.check_tlp, False)
        self.assertEqual(self.analyzer.max_tlp, 2)
        self.assertEqual(self.analyzer.http_proxy, None)
        self.assertEqual(self.analyzer.https_proxy, None)

        self.assertEqual(self.analyzer.get_param('dataType'), "ip")
        print('')

    def test_artifact_data(self):
        self.assertEqual(self.analyzer.getData(), "8.8.8.8")
        self.assertEqual(self.analyzer.get_data(), "8.8.8.8")

    def test_params_data(self):
        self.assertEqual(self.analyzer.getParam('data'), "8.8.8.8")
        self.assertEqual(self.analyzer.get_param('data'), "8.8.8.8")

class TestProxyConfig(unittest.TestCase):

    def setUp(self):
        load_test_fixture('test-proxy-config.json')
        self.analyzer = Analyzer()

    def test_proxy_config(self):
        proxy_url = 'http://local.proxy:8080'

        self.assertEqual(self.analyzer.http_proxy, proxy_url)
        self.assertEqual(self.analyzer.https_proxy, proxy_url)

        self.assertEqual(os.environ['http_proxy'], proxy_url)
        self.assertEqual(os.environ['https_proxy'], proxy_url)

if __name__ == '__main__':
    unittest.main()
