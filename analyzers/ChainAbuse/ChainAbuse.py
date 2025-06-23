#!/usr/bin/env python3
# encoding: utf-8

import requests
from cortexutils.analyzer import Analyzer


class ChainAbuse(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.key = self.get_param('config.key', None, 'Missing ChainAbuse API key')

    def summary(self, raw):
        color = 0
        taxonomies = []
        level = 'info'
        namespace = 'ChainAbuse'
        predicate = 'Report count'
        value = "0"
        count = raw.get("count") or raw.get("total") \
                or len(raw.get("data", []))

        value = str(count)
        color = count

        if color == 0:
            level = "safe"
        elif color < 5:
            level = "suspicious"
        elif color > 4:
            level = "malicious"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)
        try:
            data = self.get_data()
            s = requests.Session()
            url = "https://api.chainabuse.com/v0/reports"
            headers = {
                "accept": "application/json"
            }
            params = {
                "address": data
            }
            # ChainAbuse uses HTTP Basic Auth where the API-key is passed as both user & password
            response_details = s.get(
                url,
                params=params,
                auth=(self.key, self.key),
                headers=headers,
                timeout=30
            )                
            if response_details.status_code == 200:
                try:
                    result = response_details.json()
                    if isinstance(result, list):
                        print("Warning: Got a list, not an object. Raw output:", result)
                        result = {"data": result, "count": len(result)}
                except Exception as e:
                    return self.error(f"Could not decode JSON: {str(e)}")
                self.report(result if len(result) > 0 else {})
            else:
                self.error(f'Failed to query ChainAbuse details. Status_code {response_details.status_code}, content: {response_details.text}')
        except Exception as e:
            self.error(f'Unexpected error: {str(e)}')


if __name__ == '__main__':
    ChainAbuse().run()
