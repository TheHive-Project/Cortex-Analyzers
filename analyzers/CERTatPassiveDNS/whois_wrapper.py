#!/usr/bin/env python3
import os
from subprocess import check_output


def __query(domain, limit=100):
    """Using the shell script to query pdns.cert.at is a hack, but python raises an error every time using subprocess
    functions to call whois. So this hack is avoiding calling whois directly. Ugly, but works.

    :param domain: The domain pdns is queried with.
    :type domain: str
    :param limit: Maximum number of results
    :type limit: int
    :returns: str -- Console output from whois call.
    :rtype: str
    """
    s = check_output(['{}'.format(os.path.join(os.path.dirname(__file__), 'whois.sh')), '--limit {} {}'.format(limit, domain)], universal_newlines=True)
    return s


def __process_results(results):
    """Processes the result from __query to get valid json from every entry.

    :param results: Results from __query
    :type results: str
    :returns: python list of dictionaries containing the relevant results.
    :rtype: list
    """
    if 'no match' in results and 'returning 0 elements' in results:
        return []

    result_list = []

    # Splts the result and cuts first and last dataset which are comments
    split = results.split(sep='\n\n')[1:-1]

    for entry in split:
        entry_dict = {}
        for value in entry.split('\n'):
            if len(value) < 1:
                continue
            (desc, val) = value.split(': ')
            entry_dict[desc.replace('-', '')] = val.strip(' ')
        result_list.append(entry_dict)
    return result_list


def query(domain: str, limit: int=100):
    """Queries and returns a python dict with results.

    :param domain: domain that should be queried
    :type domain: str
    :param limit: number of entries to return
    :type limit: int
    :returns: query results
    :rtype: list
    """
    return __process_results(__query(domain, limit))
