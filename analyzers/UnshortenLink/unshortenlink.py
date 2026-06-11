#!/usr/bin/env python3
# encoding: utf-8

import ipaddress
import socket
import requests
from urllib.parse import urlparse
from cortexutils.analyzer import Analyzer

_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")  # not flagged by is_private


def _ip_blocked(ip):
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 -> 127.0.0.1
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or ip in _CGNAT_NET
    )


def _is_ssrf_target(url):
    host = urlparse(url).hostname
    if not host:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True
    for _, _, _, _, sockaddr in infos:
        addr = sockaddr[0].split("%")[0]  # strip IPv6 scope id
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return True
        if _ip_blocked(ip):
            return True
    return False


class UnshortenlinkAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.url = self.get_param('url', None)
        self.proxies = self.get_param('config.proxy', None)

    def artifacts(self, raw):
        if raw['found']:
            return [{'type': 'url', 'value': raw['url']}]
        else:
            return []

    def summary(self, raw):
        taxonomies = []
        level = 'info'
        namespace = 'UnshortenLink'
        predicate = 'Result'
        value = ''

        if raw['found'] == True:
            value = 'success'
        else:
            value = 'failure'
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)

        url = self.get_data()
        if _is_ssrf_target(url):
            self.error("URL resolves to a private or reserved address not allowed.")

        if self.proxies:
            proxies = self.proxies
        else:
            proxies = {}

        result = {'found': False, 'url': None}
        try:
            response = requests.head(url, proxies=proxies,
                                    allow_redirects=False)

            if (response.status_code == 301) or (response.status_code == 302):
                result['url'] = response.headers['Location']
                result['found'] = True
        except Exception as e:
            self.unexpectedError("Service unavailable: %s" % e)

        self.report(result)


if __name__ == '__main__':
    UnshortenlinkAnalyzer().run()
