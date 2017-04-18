#!/usr/bin/env python
"""
This contains the unit tests for the extractor.
"""
import unittest

from cortexutils.extractor import Extractor


class TestExtractorValidInput(unittest.TestCase):
    """This tests the extractor with valid input."""

    def setUp(self):
        self.extractor = Extractor()

    def test_single_fqdn(self):
        self.assertEqual(
            self.extractor.check_string(value='www.google.de'),
            'fqdn',
            'FQDN single string: wrong data type.'
        )

    def test_single_fqdn_as_unicode(self):
        self.assertEqual(
            self.extractor.check_string(value=u'www.google.de'),
            'fqdn',
            'FQDN single string: wrong data type.'
        )

    def test_single_domain(self):
        self.assertEqual(
            self.extractor.check_string(value='google.de'),
            'domain',
            'domain single string: wrong data type.'
        )

    def test_single_url(self):
        self.assertEqual(
            self.extractor.check_string(value='https://google.de'),
            'url',
            'url single string: wrong data type.'
        )

    def test_single_ipv4(self):
        self.assertEqual(
            self.extractor.check_string(value='10.0.0.1'),
            'ip',
            'ipv4 single string: wrong data type.'
        )

    def test_single_ipv6(self):
        self.assertEqual(
            self.extractor.check_string(value='2001:0db8:85a3:08d3:1319:8a2e:0370:7344'),
            'ip',
            'ipv6 single string: wrong data type.'
        )

    def test_single_md5(self):
        self.assertEqual(
            self.extractor.check_string(value='b373bd6b144e7846f45a1e47ced380b8'),
            'hash',
            'md5 single string: wrong data type.'
        )

    def test_single_sha1(self):
        self.assertEqual(
            self.extractor.check_string(value='94d4d48ba9a79304617f8291982bf69a8ce16fb0'),
            'hash',
            'sha1 single string: wrong data type.'
        )

    def test_single_sha256(self):
        self.assertEqual(
            self.extractor.check_string(value='7ef8b3dc5bf40268f66721a89b95f4c5f0cc08e34836f8c3a007ceed193654d4'),
            'hash',
            'sha256 single string: wrong data type.'
        )

    def test_single_useragent(self):
        self.assertEqual(
            self.extractor.check_string(value='Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 '
                                              'Firefox/52.0'),
            'user-agent',
            'user-agent single string: wrong data type.'
        )

    def test_single_mail(self):
        self.assertEqual(
            self.extractor.check_string(value='VeryImportant@mail.org'),
            'mail',
            'mail single string: wrong data type.'
        )

    def test_single_regkey(self):
        self.assertEqual(
            self.extractor.check_string(value='HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'),
            'registry',
            'registry single string: wrong data type.'
        )

    def test_iterable(self):
        l_real = self.extractor.check_iterable({
            'results': [
                {
                    'This is an totally unimportant key': '127.0.0.1'
                },
                {
                    'Totally nested!': ['https://nestedurl.verynested.com']
                }
            ],
            'some_more': '7ef8b3dc5bf40268f66721a89b95f4c5f0cc08e34836f8c3a007ceed193654d4',
            'another_list': ['google.de', 'bing.com', 'www.fqdn.de']
        })
        l_expected = [
            {
                'type': 'hash',
                'value': '7ef8b3dc5bf40268f66721a89b95f4c5f0cc08e34836f8c3a007ceed193654d4'
            },
            {
                'type': 'ip',
                'value': '127.0.0.1'
            },
            {
                'type': 'url',
                'value': 'https://nestedurl.verynested.com'
            },
            {
                'type': 'domain',
                'value': 'google.de'
            },
            {
                'type': 'domain',
                'value': 'bing.com'
            },
            {
                'type': 'fqdn',
                'value': 'www.fqdn.de'
            }
        ]

        # Sorting the lists
        l_real = sorted(l_real, key=lambda k: k['value'])
        l_expected = sorted(l_expected, key=lambda k: k['value'])

        self.assertEqual(
            l_real,
            l_expected,
            'Check_iterable: wrong list returned.'
        )
