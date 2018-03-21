#!/usr/bin/env python
# coding: utf-8
import json
import unittest
import sys

from cortexutils.analyzer import Analyzer

# Different lib when using python3 or 2
if sys.version_info >= (3, 0):
    from io import StringIO
else:
    from StringIO import StringIO


class AnalyzerExtractorOutputTest(unittest.TestCase):
    def setUp(self):
        sys.stdin = StringIO(json.dumps({
            "data": "8.8.8.8",
            "dataType": "ip"
        }))
        sys.stdout = StringIO()
        self.analyzer = Analyzer()

    def test_output(self):
        # Run the report method
        self.analyzer.report({'result': '1.2.3.4'})

        # Grab the output
        output = self.analyzer.fpoutput.getvalue().strip()
        json_output = json.loads(output)

        # Checks
        self.assertNotIn(self.analyzer.get_data(), output)
        self.assertEqual(json_output['artifacts'][0]['value'], '1.2.3.4')
        self.assertEqual(json_output['artifacts'][0]['type'], 'ip')

class AnalyzerExtractorNoResultTest(unittest.TestCase):
    def setUp(self):
        sys.stdin = StringIO(json.dumps({
            "data": "8.8.8.8",
            "dataType": "ip"
        }))
        sys.stdout = StringIO()
        self.analyzer = Analyzer()

    def test_output(self):
        # Run report method
        self.analyzer.report({
            'message': '8.8.8.8 was not found in database.'
        })

        # Grab the output
        output = self.analyzer.fpoutput.getvalue().strip()
        json_output = json.loads(output)

        # Check for empty artifact list
        self.assertEqual(json_output['artifacts'], [], 'Artifact list should be empty.')