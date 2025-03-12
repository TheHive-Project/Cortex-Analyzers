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
        
        if raw["status"] == "found_record":
            taxonomies.append(self.build_taxonomy(level, namespace, 'last_seen', raw['last_seen']))
            taxonomies.append(self.build_taxonomy(level, namespace, 'detection_pct', raw['detection_pct']))

        return {"taxonomies": taxonomies}

    def split_hash_labels(self, hash_str, size=32):
        """Split hash into DNS-compliant labels."""
        return '.'.join(hash_str[i:i+size] for i in range(0, len(hash_str), size))

    def run(self):
        hash_labels = self.split_hash_labels(self.observable)
        domain = f"{hash_labels}.malware.hash.cymru.com"

        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_record = rdata.strings[0].decode('utf-8')
                last_seen_epoch, detection_pct = txt_record.split()[:2]

                last_seen = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(last_seen_epoch)))

                self.report({
                    'last_seen': last_seen,
                    'detection_pct': detection_pct,
                    'status': "found_record"
                })
                return

        except dns.resolver.NXDOMAIN:
            self.report({'status': f"No record found for {self.observable}"})       
        except dns.resolver.Timeout:
            self.error(f"Timeout querying DNS for {domain}")
        except dns.resolver.NoAnswer:
            self.error(f"No answer received from DNS query for {domain}")
        except Exception as e:
            self.error(f"Unexpected error: {str(e)}")

if __name__ == '__main__':
    TeamCymruMHRAnalyzer().run()