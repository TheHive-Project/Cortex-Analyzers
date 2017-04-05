import os
import sys
import unittest
import StringIO

from cortexutils.analyzer import Analyzer

class TestMinimalConfig(unittest.TestCase):

    def setUp(self):
        path = os.path.dirname(os.path.abspath(__file__))
        with open(path + '/test-minimal-config.json', 'r') as content_file:
            input = content_file.read()
            sys.stdin = StringIO.StringIO(input)
            self.analyzer = Analyzer()

    def test_default_config(self):
        self.assertEqual(self.analyzer.data_type, 'ip')
        self.assertEqual(self.analyzer.tlp, 2)
        self.assertEqual(self.analyzer.check_tlp, False)
        self.assertEqual(self.analyzer.max_tlp, 10)
        self.assertEqual(self.analyzer.http_proxy, None)
        self.assertEqual(self.analyzer.https_proxy, None)

    def test_artifact_data(self):
        self.assertEqual(self.analyzer.getData(), "8.8.8.8")

class TestProxyConfig(unittest.TestCase):

    def setUp(self):
        path = os.path.dirname(os.path.abspath(__file__))
        with open(path + '/test-proxy-config.json', 'r') as content_file:
            input = content_file.read()
            sys.stdin = StringIO.StringIO(input)
            self.analyzer = Analyzer()

    def test_proxy_config(self):
        proxy_url = 'http://local.proxy:8080'

        self.assertEqual(self.analyzer.http_proxy, proxy_url)
        self.assertEqual(self.analyzer.https_proxy, proxy_url)

        self.assertEqual(os.environ['http_proxy'], proxy_url)
        self.assertEqual(os.environ['https_proxy'], proxy_url)

if __name__ == '__main__':
    unittest.main()
