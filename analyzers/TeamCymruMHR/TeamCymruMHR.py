#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import dns.resolver
import time

class TeamCymruMHRAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.observable = self.get_param('data', None, 'Data missing!')

    def summary(self, raw):
        taxonomies = []
        level = 'info'
        namespace = 'TeamCymruMHR'
        
        # Set predicate for last_seen
        predicate = 'last_seen'
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, raw['last_seen']))
        
        # Set predicate for detection percentage
        predicate = 'detection_pct'
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, raw['detection_pct']))

        return {"taxonomies": taxonomies}

    def run(self):
        lookup = dns.resolver.query(self.observable + '.malware.hash.cymru.com', 'TXT')
        for rdata in lookup:
            for txt_string in rdata.strings:
                last_seen_epoch = str(txt_string).split("\'")[1].split(" ")[0]
                # Make timestamp mor readable for humans, but maintain UTC
                last_seen = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(last_seen_epoch)))
                detection_pct = str(txt_string).split("\'")[1].split(" ")[1]
        self.report({ 'last_seen': last_seen, 'detection_pct': detection_pct })

if __name__ == '__main__':
    TeamCymruMHRAnalyzer().run()
