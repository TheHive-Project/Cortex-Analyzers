# Copyright (c) 2009-2021 Qintel, LLC
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError
from time import sleep
from json import loads
import os
from copy import deepcopy
from datetime import datetime, timedelta
from gzip import GzipFile

VERSION = '1.0.1'
USER_AGENT = 'integrations-helper'
MAX_RETRY_ATTEMPTS = 5

DEFAULT_HEADERS = {
    'User-Agent': f'{USER_AGENT}/{VERSION}'
}

REMOTE_MAP = {
    'pmi': 'https://api.pmi.qintel.com',
    'qwatch': 'https://api.qwatch.qintel.com',
    'qauth': 'https://api.qauth.qintel.com',
    'qsentry_feed': 'https://qsentry.qintel.com',
    'qsentry': 'https://api.qsentry.qintel.com'
}

ENDPOINT_MAP = {
    'pmi': {
        'ping': '/users/me',
        'cve': 'cves'
    },
    'qsentry_feed': {
        'anon': '/files/anonymization',
        'mal_hosting': '/files/malicious_hosting'
    },
    'qsentry': {},
    'qwatch': {
        'ping': '/users/me',
        'exposures': 'exposures'
    },
    'qauth': {}
}


def _get_request_wait_time(attempts):
    """ Use Fibonacci numbers for determining the time to wait when rate limits
    have been encountered.
    """

    n = attempts + 3
    a, b = 1, 0
    for _ in range(n):
        a, b = a + b, a

    return a


def _search(**kwargs):
    remote = kwargs.get('remote')
    max_retries = int(kwargs.get('max_retries', MAX_RETRY_ATTEMPTS))
    params = kwargs.get('params', {})
    headers = _set_headers(**kwargs)

    logger = kwargs.get('logger')

    params = urlencode(params)
    url = remote + "?" + params
    req = Request(url, headers=headers)

    request_attempts = 1
    while request_attempts < max_retries:
        try:
            return urlopen(req)

        except HTTPError as e:
            response = e

        except Exception as e:
            raise Exception('API connection error') from e

        if response.code not in [429, 504]:
            raise Exception(f'API connection error: {response}')

        if request_attempts < max_retries:
            wait_time = _get_request_wait_time(request_attempts)

            if response.code == 429:
                msg = 'rate limit reached on attempt {request_attempts}, ' \
                      'waiting {wait_time} seconds'

                if logger:
                    logger(msg)

            else:
                msg = f'connection timed out, retrying in {wait_time} seconds'
                if logger:
                    logger(msg)

            sleep(wait_time)

        else:
            raise Exception('Max API retries exceeded')

        request_attempts += 1


def _set_headers(**kwargs):
    headers = deepcopy(DEFAULT_HEADERS)

    if kwargs.get('user_agent'):
        headers['User-Agent'] = \
            f"{kwargs['user_agent']}/{USER_AGENT}/{VERSION}"

    # TODO: deprecate
    if kwargs.get('client_id') or kwargs.get('client_secret'):
        try:
            headers['Cf-Access-Client-Id'] = kwargs['client_id']
            headers['Cf-Access-Client-Secret'] = kwargs['client_secret']
        except KeyError:
            raise Exception('missing client_id or client_secret')

    if kwargs.get('token'):
        headers['x-api-key'] = kwargs['token']

    return headers


def _set_remote(product, query_type, **kwargs):
    remote = kwargs.get('remote')
    endpoint = kwargs.get('endpoint', ENDPOINT_MAP[product].get(query_type))

    if not remote:
        remote = REMOTE_MAP[product]

    if not endpoint:
        raise Exception('invalid search type')

    remote = remote.rstrip('/')
    endpoint = endpoint.lstrip('/')

    return f'{remote}/{endpoint}'


def _process_qsentry(resp):
    if resp.getheader('Content-Encoding', '') == 'gzip':
        with GzipFile(fileobj=resp) as file:
            for line in file.readlines():
                yield loads(line)


def search_pmi(search_term, query_type, **kwargs):
    """
    Search PMI

    :param str search_term: Search term
    :param str query_type: Query type [cve|ping]
    :param dict kwargs: extra client args [remote|token|params]
    :return: API JSON response object
    :rtype: dict
    """

    kwargs['remote'] = _set_remote('pmi', query_type, **kwargs)
    kwargs['token'] = kwargs.get('token', os.getenv('PMI_TOKEN'))

    params = kwargs.get('params', {})
    params.update({'identifier': search_term})
    kwargs['params'] = params

    return loads(_search(**kwargs).read())


def search_qwatch(search_term, search_type, query_type, **kwargs):
    """
    Search QWatch for exposed credentials

    :param str search_term: Search term
    :param str search_type: Search term type [domain|email]
    :param str query_type: Query type [exposures]
    :param dict kwargs: extra client args [remote|token|params]
    :return: API JSON response object
    :rtype: dict
    """

    kwargs['remote'] = _set_remote('qwatch', query_type, **kwargs)
    kwargs['token'] = kwargs.get('token', os.getenv('QWATCH_TOKEN'))

    params = kwargs.get('params', {})
    if search_type:
        params.update({search_type: search_term})
    kwargs['params'] = params

    return loads(_search(**kwargs).read())


def search_qauth(search_term, **kwargs):
    """
    Search QAuth

    :param str search_term: Search term
    :param dict kwargs: extra client args [remote|token|params]
    :return: API JSON response object
    :rtype: dict
    """

    if not kwargs.get('endpoint'):
        kwargs['endpoint'] = '/'

    kwargs['remote'] = _set_remote('qauth', None, **kwargs)
    kwargs['token'] = kwargs.get('token', os.getenv('QAUTH_TOKEN'))

    params = kwargs.get('params', {})
    params.update({'q': search_term})
    kwargs['params'] = params

    return loads(_search(**kwargs).read())


def search_qsentry(search_term, **kwargs):
    """
    Search QSentry

    :param str search_term: Search term
    :param dict kwargs: extra client args [remote|token|params]
    :return: API JSON response object
    :rtype: dict
    """

    if not kwargs.get('endpoint'):
        kwargs['endpoint'] = '/'

    kwargs['remote'] = _set_remote('qsentry', None, **kwargs)
    kwargs['token'] = kwargs.get('token', os.getenv('QSENTRY_TOKEN'))

    params = kwargs.get('params', {})
    params.update({'q': search_term})
    kwargs['params'] = params

    return loads(_search(**kwargs).read())


def qsentry_feed(query_type='anon', feed_date=datetime.today(), **kwargs):
    """
    Fetch the most recent QSentry Feed

    :param str query_type: Feed type [anon|mal_hosting]
    :param dict kwargs: extra client args [remote|token|params]
    :param datetime feed_date: feed date to fetch
    :return: API JSON response object
    :rtype: Iterator[dict]
    """

    remote = _set_remote('qsentry_feed', query_type, **kwargs)
    kwargs['token'] = kwargs.get('token', os.getenv('QSENTRY_TOKEN'))

    feed_date = (feed_date - timedelta(days=1)).strftime('%Y%m%d')
    kwargs['remote'] = f'{remote}/{feed_date}'

    resp = _search(**kwargs)
    for r in _process_qsentry(resp):
        yield r
