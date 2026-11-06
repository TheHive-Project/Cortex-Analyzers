#!/usr/bin/env python3
"""
Unittests for the WOT analyzer's summary taxonomy.
"""
import importlib.util
import io
import json
import os
import sys
import unittest

__abspath__ = os.path.dirname(os.path.abspath(__file__))

_spec = importlib.util.spec_from_file_location(
    'WOT_lookup', os.path.join(__abspath__, 'WOT_lookup.py'))
WOT_lookup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(WOT_lookup)

JOB_INPUT = json.dumps({
    'data': 'example.com',
    'dataType': 'domain',
    'tlp': 0,
    'pap': 0,
    'config': {
        'user': 'dummy_user',
        'key': 'dummy_key',
        'check_tlp': False,
        'check_pap': False,
    },
})


def new_analyzer():
    """Build the analyzer the way Cortex does, by feeding the job on stdin."""
    sys.stdin = io.StringIO(JOB_INPUT)
    return WOT_lookup.WOTAnalyzer()


class TestWOTSummary(unittest.TestCase):

    def setUp(self):
        self.__stdout = sys.stdout
        self.__stdin = sys.stdin

    def tearDown(self):
        sys.stdout = self.__stdout
        sys.stdin = self.__stdin

    def _report(self, raw):
        """Drive Analyzer.report, which is what the analyzer calls in run()."""
        analyzer = new_analyzer()
        sys.stdout = io.StringIO()
        analyzer.report(raw)
        return json.loads(sys.stdout.getvalue())

    def test_summary_levels(self):
        """A scorecard with categories must produce a taxonomy, and the
        level must follow the lowest category id."""
        cases = (
            (101, 'malicious'),
            (201, 'suspicious'),
            (301, 'safe'),
        )
        for category_id, expected_level in cases:
            with self.subTest(category_id=category_id):
                raw = {
                    'target': 'example.com',
                    'categories': [
                        {'id': category_id, 'name': 'cat', 'confidence': 40}],
                }
                result = self._report(raw)
                taxonomies = result['summary'].get('taxonomies', [])
                self.assertEqual(len(taxonomies), 1)
                self.assertEqual(taxonomies[0]['level'], expected_level)
                self.assertEqual(taxonomies[0]['namespace'], 'WOT')

    def test_summary_without_categories(self):
        """A scorecard with no categories is a normal response and must
        still produce a taxonomy rather than an empty summary."""
        result = self._report({'target': 'example.com'})
        taxonomies = result['summary'].get('taxonomies', [])
        self.assertEqual(len(taxonomies), 1)
        self.assertEqual(taxonomies[0]['level'], 'info')

    def test_summary_blacklisted(self):
        """A blacklisted target is malicious regardless of categories."""
        result = self._report(
            {'target': 'example.com', 'blackList': ['malware']})
        taxonomies = result['summary'].get('taxonomies', [])
        self.assertEqual(len(taxonomies), 1)
        self.assertEqual(taxonomies[0]['level'], 'malicious')


if __name__ == '__main__':
    unittest.main()
