#!/usr/bin/env python3
# encoding: utf-8

from valhallaAPI.valhalla import ValhallaAPI
from cortexutils.analyzer import Analyzer


class ValhallaAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.valhalla_key = self.get_param('config.key', None, 'Missing Valhalla API key')
        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.v = ValhallaAPI(api_key=self.valhalla_key)

    def check_response(self, response):
        if type(response) is not dict:
            self.error('Bad response : ' + str(response))
        status = response.get('status', 'not set')
        if status == 'error':
            self.error('Query failed: %s Message: %s' % (str(status), response.get('message', 'not set')))
        results = response
        return results

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "VALHALLA"
        predicate = "GetMatches"
        value = "not set"

        # Get status and result set
        status = raw.get('status', 'not set')
        results = raw.get('results', [])
        
        # Status handling
        if status == "error":
            status = raw.get('message', 'not set')
            value = status
        if status == "empty":
            value = "no matches found"

        # If a single matching YARA rule could be found, then set suspicious
        if len(results) > 0:
            level = "suspicious"

        # Match handling
        av_matches = []
        avg_av_matches = 0
        matching_rules = []
        for match in results:
            # Add rule to list
            matching_rules.append(match["rulename"])
            # Sum up all AV matches
            if 'positives' in match:
                if isinstance(match['positives'], int):
                    av_matches.append(match['positives'])
        # Calculate average AV detection rate
        if len(av_matches) > 0:
            avg_av_matches = sum(av_matches)/len(av_matches)
        # If AV engines also came to the conclusion that this is malicious, then mark it as malicious
        if avg_av_matches > 10:
            level = "malicious"

        # Compose a list of all matching YARA rules for the value field
        if len(matching_rules) > 0:
            value = ", ".join(matching_rules)

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'hash':
            data = self.get_param('data', None, 'Data is missing')
            if len(data) == 64:
                self.report(self.check_response(self.v.get_hash_info(data)))
            else:
                self.report({'status': 'error', 'message': 'hash is not SHA256', 'results': []})
        else:
            self.error('Invalid data type')


if __name__ == '__main__':
    ValhallaAnalyzer().run()
