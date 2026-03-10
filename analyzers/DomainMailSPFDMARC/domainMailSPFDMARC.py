#!/usr/bin/env python3
# -*- coding: utf-8 -*

from cortexutils.analyzer import Analyzer

import checkdmarc
import email
import email.policy
import email.utils

class DomainMailSPFDMARC(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.name = "DomainMailSPFDMARC"

    def _find_inner_message(self, msg):
        """Walk MIME parts to find an attached original email (message/rfc822).
        This handles reported/forwarded emails where the actual sender is nested."""
        for part in msg.walk():
            if part.get_content_type() == "message/rfc822":
                payload = part.get_payload()
                if isinstance(payload, list) and len(payload) > 0:
                    return payload[0]
                elif hasattr(payload, "get"):
                    return payload
        return None

    def extract_domain_from_eml(self, filepath):
        with open(filepath, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=email.policy.default)
        # If the email contains a nested message (reported/forwarded), use the inner one
        inner = self._find_inner_message(msg)
        if inner:
            msg = inner
        from_header = msg.get("From", "")
        # Extract email address from "Display Name <user@domain.com>" format
        addr = email.utils.parseaddr(from_header)[1]
        if not addr or "@" not in addr:
            self.error("Could not extract sender email address from .eml file")
        return addr.split("@")[1]

    def summary(self, raw):
        taxonomies = []
        namespace = "DomainMailSPF_DMARC"

        if 'error' in raw['DomainMailSPFDMARC']['dmarc']:
            if 'error' in raw['DomainMailSPFDMARC']['spf']:
                taxonomies.append(self.build_taxonomy("malicious", namespace,"DMARC","no"))
                taxonomies.append(self.build_taxonomy("malicious", namespace,"SPF","no"))
            else:
                taxonomies.append(self.build_taxonomy("safe", namespace,"SPF","yes"))
                taxonomies.append(self.build_taxonomy("suspicious", namespace,"DMARC","no"))
        else:
            if 'error' in raw['DomainMailSPFDMARC']['spf']:
                taxonomies.append(self.build_taxonomy("suspicious", namespace,"SPF","no"))
                taxonomies.append(self.build_taxonomy("safe", namespace,"DMARC","yes"))
            else:
                taxonomies.append(self.build_taxonomy("safe", namespace,"SPF","yes"))
                taxonomies.append(self.build_taxonomy("safe", namespace,"DMARC","yes"))
        
        return {'taxonomies': taxonomies}
        
    def get_info(self, data):
        try:
            result = checkdmarc.check_domains(data.split()) 
        except Exception as e :
            self.error(e)
        return {"DomainMailSPFDMARC": dict(result)}

    def run(self):
        if self.data_type in ('domain', 'fqdn'):
            self.report(self.get_info(self.get_data()))
        elif self.data_type == 'file':
            filepath = self.get_param('file', None, 'File is missing')
            filename = self.get_param('filename', '')
            if not filename.lower().endswith('.eml'):
                self.error('Only .eml files are supported.')
            domain = self.extract_domain_from_eml(filepath)
            self.report(self.get_info(domain))
        else:
            self.error('Data type not supported. Please use this analyzer with data types domain, fqdn, or file (.eml).')

if __name__ == '__main__':
    DomainMailSPFDMARC().run()
