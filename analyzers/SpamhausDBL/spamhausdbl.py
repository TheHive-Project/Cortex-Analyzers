#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import dns.resolver

class SpamhausDBLAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.observable = self.get_param('data', None, 'Data missing!')

    def summary(self, raw):
        taxonomies = []
        level = 'info'
        namespace = 'SpamhausDBL'
      
        # Set predicate for return_code
        predicate = 'return_code'
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, raw['return_code']))
 
        # Set predicate for classification
        predicate = 'classification'
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, raw['classification']))
  
        return {"taxonomies": taxonomies}
   
    def run(self):
        try:
            lookup = dns.resolver.query(self.observable + '.dbl.spamhaus.org')
            return_code = str(lookup[0])
            # Check return code for result info
            # Reference here: https://www.spamhaus.org/faq/section/Spamhaus%20DBL#291

            # spam domain
            if return_code == "127.0.1.2" :
                classification = "Spam"

            # phish domain
            if return_code == "127.0.1.4" :
                classification = "Phishing"

            # malware domain
            if return_code == "127.0.1.5" :
                classification = "Malware"

            # botnet C&C domain
            if return_code == "127.0.1.6" :
                classification = "Botnet C&C"

            # abused legit spam
            if return_code == "127.0.1.102" :
                classification = "Abused legit spam"

            # abused spammed redirector domain
            if return_code == "127.0.1.103" :
                classification = "Abused spammed redirector"

            # abused legit phish
            if return_code == "127.0.1.104" :
                classification = "Abused legit phish"

            # abused legit malware
            if return_code == "127.0.1.105" :
                classification = "Abused legit malware"

            # abused legit botnet C&C
            if return_code == "127.0.1.106" :
                classification = "Abused legit Botnet C&C"

            # IP queries prohibited
            if return_code == "127.0.1.255" :
                classification = "IP queries prohibited"

            # Typing error in DNSBL name
            if return_code == "127.255.255.252" :
                classification = "Typing error in DNSBL name"

            # Anon query through public resolver
            if return_code == "127.255.255.254" :
                classification = "Anon query through public resolver"

            # Excessive number of queries
            if return_code == "127.255.255.255" :
                classification = "Excessive number of queries"

            self.report({ 'return_code': return_code, 'classification': classification })
        
        except dns.resolver.NXDOMAIN:
            self.report({ 'return_code': 'NXDOMAIN', 'classification': 'Clean' })
        except dns.resolver.NoAnswer:
            self.report({ 'return_code': 'NoAnswer', 'classification': 'NoAnswer' })
        except dns.resolver.Timeout:
            self.report({ 'return_code': 'Timeout', 'classification': 'Timeout' })
        except:
            self.error('Something unexpected happened!')

if __name__ == '__main__':
    SpamhausDBLAnalyzer().run()
    
