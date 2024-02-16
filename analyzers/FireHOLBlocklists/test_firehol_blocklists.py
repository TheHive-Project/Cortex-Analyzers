#!/usr/bin/env python3
"""
Unittests for firehol blocklists analyzer
"""
import io
import json
import os
import unittest
import sys
from .firehol_blocklists import FireholBlocklistsAnalyzer


__abspath__ = os.path.dirname(os.path.abspath(__file__))
__stdout__ = sys.stdout
sys.path.insert(0, __abspath__)


def load_data(file: str):
    with io.open(os.path.join(__abspath__, 'test_data', file)) as afile:
        input_str = afile.read().replace('PATH', os.path.join(__abspath__, 'test_data'))
    sys.stdin = io.StringIO(input_str)
    sys.stdout = io.StringIO()


class TestFireholBlocklistsValidData(unittest.TestCase):
    def setUp(self):
        load_data('test_firehol_blocklists.json')
        self.analyzer = FireholBlocklistsAnalyzer()

    def test_path(self):
        self.assertEqual(self.analyzer.path, os.path.join(__abspath__, 'test_data'), 'Wrong path.')

    def test_type(self):
        self.assertEqual(self.analyzer.data_type, 'ip', 'Wrong data type.')

    def test_results(self):
        self.analyzer.run()
        results = json.loads(sys.stdout.getvalue())
        self.assertEqual(results.get('full').get('count'), 2, 'Number of hits are wrong.')
        for hit in results.get('full').get('hits'):
            self.assertTrue(hit.get('list') == 'ips' or hit.get('list') == 'net', 'Expected lists are wrong.')
