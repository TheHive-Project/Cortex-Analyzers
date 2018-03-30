#!/usr/bin/env python
from builtins import str as unicode

import re


class ExtractionError(Exception):
    pass


class Extractor:
    """
    The extractor class tries to detect ioc attribute types using regex-matching. Two functions are provided:
      - ``check_string(str)`` which checks a string for a regex match and just returns the type
      - ``check_iterable(itr)`` that iterates over a list or a dictionary and returns a list of {type, value} dicts

    Currently, this is not a fulltext search, so the the ioc's must be isolated strings, to get found.
    This can be iterated for ioc's.

    :param ignore: List of strings or a single string to ignore when matching artifacts to type
    :type ignore: list, str
    """

    def __init__(self, ignore=None):
        self.ignore = ignore
        self.regex = self.__init_regex()

    @staticmethod
    def __init_regex():
        """
        Returns compiled regex list.

        :return: List of {type, regex} dicts
        :rtype: list
        """

        # IPv4
        regex = [{
            'type': 'ip',
            'regex': re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
        }]

        # IPv6
        # RegEx from https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
        r = '(' + \
            '([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|' + \
            '([0-9a-fA-F]{1,4}:){1,7}:|' + \
            '([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|' + \
            '([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|' + \
            '([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|' + \
            '([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|' + \
            '([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|' + \
            '[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|' + \
            ':((:[0-9a-fA-F]{1,4}){1,7}|:)|' + \
            'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|' + \
            '::(ffff(:0{1,4}){0,1}:){0,1}' + \
            '((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}' + \
            '(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|' + \
            '([0-9a-fA-F]{1,4}:){1,4}:' + \
            '((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}' + \
            '(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])' + \
            ')'
        regex.append({
            'type': 'ip',
            'regex': re.compile(r'{}'.format(r))
        })

        # URL
        regex.append({
            'type': 'url',
            'regex': re.compile(r'^(http://|https://)')
        })

        # domain
        regex.append({
            'type': 'domain',
            'regex': re.compile(r'^(?!http://|https://)^[\w\-]+\.[a-zA-Z]+$')
        })

        # hash
        regex.append({
            'type': 'hash',
            'regex': re.compile(r'^([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$')
        })

        # user-agent
        regex.append({
            'type': 'user-agent',
            'regex': re.compile(r'^(Mozilla/[45]\.0 |AppleWebKit/[0-9]{3}\.[0-9]{2} |Chrome/[0-9]{2}\.[0-9]\.'
                                r'[0-9]{4}\.[0-9]{3} |Safari/[0-9]{3}\.[0-9]{2} ).*?$')
        })

        # uri_path
        regex.append({
            'type': 'uri_path',
            'regex': re.compile(r'^(?!http://|https://)[A-Za-z]*://')
        })

        # regkey
        regex.append({
            'type': 'registry',
            'regex': re.compile(r'^(HKEY|HKLM|HKCU|HKCR|HKCC)'
                                r'(_LOCAL_MACHINE|_CURRENT_USER|_CURRENT_CONFIG|_CLASSES_ROOT|)[\\a-zA-Z0-9]+$')
        })

        # mail
        regex.append({
            'type': 'mail',
            'regex': re.compile(r'[\w.\-]+@\w+\.[\w.]+')
        })

        # fqdn
        regex.append({
            'type': 'fqdn',
            'regex': re.compile(r'^(?!http://|https://)^[\w\-.]+\.[\w\-]+\.[a-zA-Z]+$')
        })

        return regex

    def __checktype(self, value):
        """Checks if the given value is a known datatype

        :param value: The value to check
        :type value: str or number
        :return: Data type of value, if known, else empty string
        :rtype: str
        """
        if self.ignore:
            if isinstance(value, str) and self.ignore in value:
                return ''
            if self.ignore == value:
                return ''

        if isinstance(value, (str, unicode)):
            for r in self.regex:
                if r.get('regex').match(value):
                    return r.get('type')
        return ''

    def check_string(self, value):
        """
        Checks if a string matches a datatype.

        :param value: String to test
        :type value: str
        :return: Data type or empty string
        :rtype: str
        """
        return self.__checktype(value)

    def check_iterable(self, iterable):
        """
        Checks values of a list or a dict on ioc's. Returns a list of dict {type, value}. Raises TypeError, if iterable
        is not an expected type.

        :param iterable: List or dict of values
        :type iterable: list dict str
        :return: List of ioc's matching the regex
        :rtype: list
        """
        results = []
        # Only the string left
        if isinstance(iterable, (str, unicode)):
            dt = self.__checktype(iterable)
            if len(dt) > 0:
                results.append({
                    'type': dt,
                    'value': iterable
                })
        elif isinstance(iterable, list):
            for item in iterable:
                if isinstance(item, list) or isinstance(item, dict):
                    results.extend(self.check_iterable(item))
                else:
                    dt = self.__checktype(item)
                    if len(dt) > 0:
                        results.append({
                            'type': dt,
                            'value': item
                        })
        elif isinstance(iterable, dict):
            for _, item in iterable.items():
                if isinstance(item, list) or isinstance(item, dict):
                    results.extend(self.check_iterable(item))
                else:
                    dt = self.__checktype(item)
                    if len(dt) > 0:
                        results.append({
                            'type': dt,
                            'value': item
                        })
        else:
            raise TypeError('Not supported type.')

        return results
