#!/usr/bin/env python3
# encoding: utf-8

import cloudscraper
from cortexutils.analyzer import Analyzer


class TalosReputation(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

    def summary(self, raw):
        taxonomies = []
        level = 'info'  # If there's a change of naming, will be presented as info
        namespace = 'Talos'
        predicate = 'Reputation'
        value = raw.get('email_score_name')
        if value == 'Good':
            level = 'safe'
        elif value == 'Poor':
            level = 'malicious'
        elif value == 'Neutral':
            level = 'suspicious'
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)
        if self.data_type == 'ip':
            try:
                data = self.get_data()

                scraper = cloudscraper.CloudScraper()

                headers = {
                    'Host': 'talosintelligence.com',
                    'Referer': 'https://talosintelligence.com/reputation_center/lookup?search={}'.format(data),
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
                    'Accept': 'application/json'
                }

                response_details = scraper.get('https://talosintelligence.com/sb_api/query_lookup',
                    headers = headers,
                    params = {
                        'query': '/api/v2/details/ip/',
                        'query_entry': data
                        }
                    )

                response_location = scraper.get('https://talosintelligence.com/sb_api/query_lookup',
                    headers = headers,
                    params = {
                        'query': '/api/v2/location/ip/',
                        'query_entry': data
                        }
                    )

                if response_details.status_code == 200 | 201:
                    if response_location.status_code == 200 | 201:
                        result = response_details.json()
                        result['country'] = response_location.json().get('country', None)
                        self.report(result if len(result) > 0 else {})
                    else:
                        self.error('Failed to query Talos location. Status_code {}'.format(response_location.status_code))
                else:
                    self.error('Failed to query Talos details. Status_code {}'.format(response_details.status_code))
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    TalosReputation().run()
