#!/usr/bin/env python3

import requests
from cortexutils.analyzer import Analyzer

class LupovisProwlAnalyzer(Analyzer):
    def __init__(self):
        super().__init__()
        self.prowl_api_key = self.get_param("config.prowl_api_key", None, "Missing API key")
        self.prowl_api_url = 'https://api.prowl.lupovis.io/GetIPReputation?ip='
        self.proxy = {
            "http": self.get_param("config.proxy.http", None),
            "https": self.get_param("config.proxy.https", None)
        }

    def summary(self, raw):
        ttps = raw.get('ttps', [])
        level = 'malicious' if ttps else 'safe'
        return [{
            'level': level,
            'namespace': 'LupovisProwlAnalyzer',
            'predicate': 'Threat',
            'value': ttps[0] if ttps else 'No known malicious activity'
        }]

    def build_taxonomy(self, level, namespace, predicate, value):
        return {
            'level': level,
            'namespace': namespace,
            'predicate': predicate,
            'value': value
        }

    def run(self):
        ip = self.get_data()
        if not ip:
            self.error('No IP provided')
            return

        url = f"{self.prowl_api_url}{ip}"
        headers = {"x-api-key": self.prowl_api_key}

        try:
            response = requests.get(url, headers=headers, proxies=self.proxy, timeout=10)
            if response.status_code != 200:
                self.error(f"API returned error {response.status_code}: {response.text}")
                return

            data = response.json()
            ttps = data.get('ttps', [])
            level = 'malicious' if ttps else 'safe'
            value = ttps[0] if ttps else 'No known malicious activity'

            self.report({
                "ip": ip,
                "ttps": ttps,
                "taxonomy": self.build_taxonomy(level, 'LupovisProwlAnalyzer', 'Threat', value)
            })

        except requests.exceptions.RequestException as e:
            self.error(f"Request failed: {e}")

if __name__ == '__main__':
    LupovisProwlAnalyzer().run()
