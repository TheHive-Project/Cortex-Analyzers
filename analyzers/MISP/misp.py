#!/usr/bin/env python
from cortexutils.analyzer import Analyzer
from mispclient import MISPClient, MISPClientError


class MISPAnalyzer(Analyzer):
    """Searches for given IOCs in configured misp instances. All standard data types are supported."""

    def __init__(self):
        Analyzer.__init__(self)

        # Fixes #94. Instead of None, the string Unnamed should be passed to MISPClient constructor
        name = self.getParam('config.name', None)
        if not name:
            name = 'Unnamed'
        try:
            self.misp = MISPClient(url=self.getParam('config.url', None, 'No MISP url given.'),
                                key=self.getParam('config.key', None, 'No MISP api key given.'),
                                ssl=self.getParam('config.certpath', True),
                                name=name)
        except MISPClientError as e:
            self.error(str(e))
        except TypeError as te:
            self.error(str(te))

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "MISP"
        predicate = "Search"
        value = "\"0\""

        data = []
        for r in raw['results']:
            for res in r['result']:
                if 'uuid' in res:
                    data.append(res['uuid'])

        # return number of unique events
        if not data:
            value = "\"0 event\""
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        else:
            value = "\"{} event(s)\"".format(len(list(set(data))))
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'hash':
            response = self.misp.search_hash(self.getData())
        elif self.data_type == 'url':
            response = self.misp.search_url(self.getData())
        elif self.data_type == 'domain' or self.data_type == 'fqdn':
            response = self.misp.search_domain(self.getData())
        elif self.data_type == 'mail' or self.data_type == 'mail_subject':
            response = self.misp.search_mail(self.getData())
        elif self.data_type == 'ip':
            response = self.misp.search_ip(self.getData())
        elif self.data_type == 'registry':
            response = self.misp.search_registry(self.getData())
        elif self.data_type == 'filename':
            response = self.misp.search_filename(self.getData())
        else:
            response = self.misp.searchall(self.getData())

        self.report({'results': response})


if __name__ == '__main__':
    MISPAnalyzer().run()
