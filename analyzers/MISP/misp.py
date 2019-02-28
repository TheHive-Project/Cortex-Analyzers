#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from mispclient import MISPClient, MISPClientError


class MISPAnalyzer(Analyzer):
    """Searches for given IOCs in configured misp instances. All standard data types are supported."""

    def __init__(self):
        Analyzer.__init__(self)

        # Fixes #94. Instead of None, the string Unnamed should be passed to MISPClient constructor
        name = self.get_param('config.name', None)
        if not name or len(name) == 0:
            name = 'Unnamed'
        if self.get_param('config.cert_check', True):
            ssl_path = self.get_param('config.cert_path', None)
            if not ssl_path or ssl_path == '':
                ssl = True
            else:
                ssl = ssl_path
        else:
            ssl = False
        try:
            self.misp = MISPClient(url=self.get_param('config.url', None, 'No MISP url given.'),
                                   key=self.get_param('config.key', None, 'No MISP api key given.'),
                                   ssl=ssl,
                                   name=name,
                                   proxies={'http': self.http_proxy, 'https': self.https_proxy})
        except MISPClientError as e:
            self.error(str(e))
        except TypeError as te:
            self.error(str(te))

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "MISP"
        predicate = "Search"

        data = []
        for r in raw['results']:
            for res in r['result']:
                if 'uuid' in res:
                    data.append(res['uuid'])

        # return number of unique events
        if not data:
            value = "0 events"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        else:
            value = "{} event(s)".format(len(list(set(data))))
            level = "suspicious"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'hash':
            response = self.misp.search_hash(self.get_data())
        elif self.data_type == 'url':
            response = self.misp.search_url(self.get_data())
        elif self.data_type == 'domain' or self.data_type == 'fqdn':
            response = self.misp.search_domain(self.get_data())
        elif self.data_type == 'mail' or self.data_type == 'mail_subject':
            response = self.misp.search_mail(self.get_data())
        elif self.data_type == 'ip':
            response = self.misp.search_ip(self.get_data())
        elif self.data_type == 'registry':
            response = self.misp.search_registry(self.get_data())
        elif self.data_type == 'filename':
            response = self.misp.search_filename(self.get_data())
        else:
            response = self.misp.searchall(self.get_data())

        self.report({'results': response})


if __name__ == '__main__':
    MISPAnalyzer().run()
