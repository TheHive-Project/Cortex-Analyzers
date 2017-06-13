#!/usr/bin/env python

import safebrowsing
from cortexutils.analyzer import Analyzer


class SafebrowsingAnalyzer(Analyzer):
    """Cortex analyzer to query Google Safebrowsing for URLs. Info how to obtain an API key can be found
    `here <https://developers.google.com/safe-browsing/v4/get-started>`_."""
    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param('config.key', None, 'No Google API key provided.')
        self.client_id = self.get_param('config.client_id', 'Cortex')
        self.client_version = '0.1'

        self.sb = safebrowsing.SafebrowsingClient(
            key=self.api_key,
            client_id=self.client_id,
            client_version=self.client_version
        )

    def summary(self, raw):

        result = {"level":"info", "taxonomy":{"namespace": "Google", "predicate": "Safebrowsing", "value":0}}

        if ("results" in raw):
            r = len(raw['results'])

        if r == 0 or r == 1:
            result["taxonomy"]["value"] = "\"{} match\"".format(r)
        else:
            result["taxonomy"]["value"] = "\"{} matches\"".format(r)

        if r > 0:
            result["level"] = "malicious"
        # level : info, safe, suspicious, malicious

        return result

    def run(self):
        report = []
        result = self.sb.query_url(self.get_data())
        for match in result.get('matches', []):
            report.append({
                'platform': match.get('platformType'),
                'threat': match.get('threatType')
            })
        self.report({'results': report})


if __name__ == '__main__':
    SafebrowsingAnalyzer().run()
