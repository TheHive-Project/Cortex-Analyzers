#!/usr/bin/env python3
# encoding: utf-8

import requests
from cortexutils.analyzer import Analyzer

# Map of tag IDs to (name,level)-tuple used in summary (tags not listed here are not shown)
tag_map = {
    'reconscanning': ('Scanner', 'suspicious'),
    'attemptexploit': ('Exploit', 'malicious'),
    'attemptlogin': ('Login', 'malicious'),
    'malware': ('Malware', 'malicious'),
    'availabilitydos': ('DDoS', 'malicious'),
    'researchscanners': ('Research scanner', 'safe'),
    'vpn': ('VPN', 'info'),
    'nat': ('NAT', 'info'),
    'dsl': ('DSL', 'info'),
    'dynamicIP': ('Dynamic IP', 'info'),
    'tor': ('Tor exit node', 'info'),
    'spam': ('Spam', 'malicious'),
    'reserved_ip': ('Reserved IP', 'info'),
}


class NERDAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.base_url = self.get_param('config.url', None, 'Config error: Missing URL of NERD.')
        if not self.base_url.endswith('/'):
            self.base_url += '/'
        self.api_key = self.get_param('config.key', None, 'Config error: Missing API key for NERD.')

    def summary(self, raw):
        """Returns a summary, needed for 'short.html' template, based on the full report"""

        taxonomies = []
        if 'message' in raw:
            # IP wasn't found
            taxonomies.append(self.build_taxonomy('safe', 'NERD', 'Rep', 'no-data'))
        else:
            # Reputation score (set level/color according to the score)
            rep = round(raw['rep'], 3)
            rep_level = 'safe' if rep < 0.02 else ('suspicious' if rep <= 0.5 else 'malicious')
            taxonomies.append(self.build_taxonomy(rep_level, 'NERD', 'Rep', rep))

            # Number of blacklists
            if raw['blacklists']:
                taxonomies.append(self.build_taxonomy('malicious', 'NERD', 'Blacklists', len(raw['blacklists'])))

            # Tags
            for tag_name,level in raw['translated_tags']:
                taxonomies.append(self.build_taxonomy(level, 'NERD', 'Tag', tag_name))

        return {'taxonomies': taxonomies}

    def artifacts(self, raw):
        """Returns a list of indicators extracted from reply (only "hostname" in this case)"""
        if raw.get('hostname'):
            return [{'dataType': 'fqdn', 'data': raw['hostname']}]
        return []

    def run(self):
        """Main function run by Cortex to analyze an observable."""
        if self.data_type != 'ip':
            self.error("Invalid data type, only IP addresses are supported")
            return
        ip = self.get_data()

        # Get data from server
        url = '{}api/v1/ip/{}'.format(self.base_url, ip)
        headers = {'Authorization': self.api_key}
        try:
            resp = requests.get(url, headers=headers)
        except Exception as e:
            self.error("Error when trying to contact server: {}".format(e))
            return

        # Parse received data
        try:
            data = resp.json()
        except ValueError:
            self.error("Unexpected or invalid response received from server (can't parse as JSON). A possible reason can be wrong URL.")
            return

        if resp.status_code == 404:
            # IP not found in NERD's DB (i.e. it wasn't reported as malicious)
            self.report({
                'rep': 0.0,
                'message': '{} not found in NERD, i.e. there are no recent reports of malicious activity.'.format(ip),
                'nerd_url': '{}ip/{}'.format(self.base_url, ip), # Link to IP's page at NERD web
            })
            return
        elif resp.status_code == 200:
            # Success, IP data received - format as output for Cortex
            try:
                # Translate tags
                translated_tags = []
                tag_ids = [t['n'] for t in data['tags'] if t.get('c', 1.0) >= 0.5] # List of tags with confidence >= 50%
                for tag in tag_ids:
                    try:
                        tag_name, level = tag_map[tag]
                    except KeyError:
                        continue
                    translated_tags.append([tag_name, level])
                # Create report
                self.report({
                    'rep': data['rep'], # reputation score (number between 0.0 to 1.0)
                    'hostname': data['hostname'], # result of DNS PTR qeury
                    'asn': data['asn'], # list of ASNs announcing the IP (usually just one)
                    'country': data['geo'].get('ctry', ''), # Geolocation - two-letter country code
                    'blacklists': data['bl'], # List of blacklists the IP is listed on
                    'tags': tag_ids, # Original Tags as in NERD
                    'translated_tags': translated_tags, # Tags filtered and translated to nicer names
                    'nerd_url': '{}ip/{}'.format(self.base_url, ip), # Link to IP's page at NERD web
                })
            except KeyError as e:
                self.error("Invalid response received from server, missing field: {}".format(e))
        else:
            # Unexpected status code, there should be an 'error' field with error message
            self.error("Error: {} {}".format(resp.status_code, data.get('error', '(no error message)')))
            return


if __name__ == '__main__':
    NERDAnalyzer().run()
