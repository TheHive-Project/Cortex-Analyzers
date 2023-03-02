#!/usr/bin/env python3
# encoding: utf-8

import os

from thunderstormAPI.thunderstorm import ThunderstormAPI
from cortexutils.analyzer import Analyzer


class ThunderstormAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.thunderstorm_server = self.get_param('config.thunderstorm_server', None, 'THOR Thunderstorm server has not been configured')
        self.thunderstorm_port = self.get_param('config.thunderstorm_port', 8080)
        self.thunderstorm_source = self.get_param('config.thunderstorm_source', 'cortex-analyzer')
        self.thunderstorm_ssl = self.get_param('config.thunderstorm_ssl', False)
        self.thunderstorm_verify_ssl = self.get_param('config.thunderstorm_ssl_verify', False)
        
        self.thorapi = ThunderstormAPI(
            host=self.thunderstorm_server, 
            port=int(self.thunderstorm_port), 
            source=self.thunderstorm_source,
            use_ssl=self.thunderstorm_ssl,
            verify_ssl=self.thunderstorm_verify_ssl)

    def check_response(self, response):
        if len(response) > 0:
            if type(response) is not list:
                self.error('Bad response : ' + str(response))
            results = response[0]
        else: 
            results = {}
        return results

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "THUNDERSTORM"
        predicate = "GetScanResult"
        value = "no matches"

        result = raw
        if len(result) > 0: 
            # A single match automatically makes it suspicious
            level = "suspicious"
            # Get THOR's level 
            thor_level = result['level']
            # If that is 'Alert', then increase the level to malicious
            if thor_level == "Alert":
                level = "malicious"
            
            # Get all matches that add a sub score to the total score
            match_reasons = []
            yara_matches = 0
            other_matches = 0
            total_score = 0
            for match in result['matches']:
                # Fix /tmp/ folder finding caused by Cortex file upload
                if "suspicious apt directory" in match['reason'].lower():
                    # ignore this match
                    continue
                # Add sub score to total score 
                if 'subscore' in match: 
                    total_score += int(match['subscore'])
                # YARA rule match
                if 'rulename' in match: 
                    match_reasons.append(match['rulename'])
                    yara_matches += 1
                else:
                    other_matches += 1
            
            # Combine all rule names to a value
            if len(match_reasons) > 0:
                if len(match_reasons) < 4:
                    value = ", ".join(match_reasons)
                else:
                    value = "[%d of different rule matches]" % len(match_reasons)
            
            # Add match type to the result set
            result['yara_matches'] = yara_matches
            result['other_matches'] = other_matches

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'file':
            data = self.get_param('file', None, 'File is missing')
            if os.path.exists(data):
                self.report(self.check_response(self.thorapi.scan(data)))
            else:
                self.error("File '%s' not found" % data)
        else:
            self.error('Invalid data type')


if __name__ == '__main__':
    ThunderstormAnalyzer().run()
