#!/usr/bin/env python3
# encoding: utf-8

from base64 import b64encode
import json
import urllib.parse
import http.client
from cortexutils.analyzer import Analyzer

class UnshortenlinkAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.url = self.getParam('url', None)
        self.proxies = self.getParam('config.proxy', None)

    def artifacts(self, raw):
        if raw['found'] == True:
            return [{'type': 'url', 'value': raw['url']}]
        else:
            return []

    def run(self):
        Analyzer.run(self)

        data = self.getData()

        if self.proxies is None:
            try:
                url_parsed = urllib.parse.urlparse(data)
    
                if url_parsed.scheme == "https":
                    h = http.client.HTTPSConnection(url_parsed.netloc)
                elif url_parsed.scheme == "http":
                    h = http.client.HTTPConnection(url_parsed.netloc)
    
                h.request('HEAD', url_parsed.path)
                response = h.getresponse()
    
                result = {'found': False, 'url': None}
    
                if (response.status == 301) or (response.status == 302):
                    result['url'] = response.getheader('Location')
                    result['found'] = True
    
                self.report(result)
            except:
                self.unexpectedError("Service unavailable")
        else:
            try:
                # use https if used
                if self.proxies.get("https"):
                    proxy_parsed = urllib.parse.urlparse(self.proxies.get("https"))
                    h = http.client.HTTPSConnection(proxy_parsed.hostname, proxy_parsed.port)
                else:
                    proxy_parsed = urllib.parse.urlparse(self.proxies.get("http"))
                    h = http.client.HTTPConnection(proxy_parsed.hostname, proxy_parsed.port)

                headers = {}
                if proxy_parsed.username and proxy_parsed.password:
                    auth = "%s:%s" % (proxy_parsed.username, proxy_parsed.password)
                    headers['Proxy-Authorization'] = 'Basic ' + b64encode(auth)

                #url_parsed = urllib.parse.urlparse(data)

                #if (url_parsed.scheme == "https") and (url_parsed.port is None):
                #    url_parsed_port = 443
                #else:
                #    url_parsed_port = url_parsed.port

                #if url_parsed.path is None:
                #    url_parsed_path = "/"
                #else:
                #    url_parsed_path = url_parsed.path

                try:
                    #h.set_tunnel(url_parsed.hostname, url_parsed_port, headers)
                    h.request('HEAD', data)
                    response = h.getresponse()
                except Exception as e:
                    self.unexpectedError("Service unavailable, exception: %s" % e)

                result = {'found': False, 'url': None}

                if (response.status == 301) or (response.status == 302):
                    result['url'] = response.getheader('Location')
                    result['found'] = True
                    self.report(result)
                    return

                self.report(result)
            except:
                self.unexpectedError("Service unavailable")

if __name__ == '__main__':
    UnshortenlinkAnalyzer().run()
