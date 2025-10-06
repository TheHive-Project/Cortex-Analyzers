#!/usr/bin/env python3
# encoding: utf-8
from typing import Optional, List

import requests
from cortexutils.analyzer import Analyzer


class Cluster25Client:
    def __init__(
            self,
            customer_id: Optional[str] = None,
            customer_key: Optional[str] = None,
            base_url: Optional[str] = None
    ):
        self.client_id = customer_id
        self.client_secret = customer_key
        self.base_url = base_url
        self.current_token = self._get_cluster25_token()
        self.headers = {"Authorization": f"Bearer {self.current_token}"}

    def _get_cluster25_token(
            self
    ) -> List[dict]:
        payload = {"client_id": self.client_id, "client_secret": self.client_secret}
        r = requests.post(url=f"{self.base_url}/token", json=payload, headers={"Content-Type": "application/json"})
        if r.status_code != 200:
            raise Exception(f"Unable to retrieve the token from C25 platform, status {r.status_code}")
        return r.json()["data"]["token"]

    def investigate(
            self,
            indicator
    ) -> dict:
        params = {'indicator': indicator.get('value')}
        r = requests.get(url=f"{self.base_url}/investigate", params=params, headers=self.headers)
        if r.status_code != 200:
            return {'error': f"Unable to retrieve investigate result for indicator '{indicator.get('value')}' "
                             f"from C25 platform, status {r.status_code}"}
        return r.json()["data"]


class C25CortexAnalyzer(Analyzer):
    def __init__(
            self
    ):
        Analyzer.__init__(self)
        self.c25_api_key = self.get_param("config.client_key", None, "Missing Cluster25 api key")
        self.c25_client_id = self.get_param("config.client_id", None, "Missing Cluster25 client id")
        self.c25_base_url = self.get_param("config.base_url", None, "Missing Cluster25 base url")
        self.c25_api_client = Cluster25Client(self.c25_client_id, self.c25_api_key, self.c25_base_url)

    def investigate(
            self,
            indicator: str
    ) -> dict:
        return self.c25_api_client.investigate({'value': indicator})

    def summary(
            self,
            indicator_data: dict
    ) -> dict:
        taxonomies = []
        namespace = "C25"
        level = 'info'
        if indicator_data.get('indicator'):
            taxonomies.append(self.build_taxonomy(level, namespace, "Indicator", indicator_data.get('indicator')))
        if indicator_data.get('indicator_type'):
            taxonomies.append(
                self.build_taxonomy(level, namespace, "Indicator Type", indicator_data.get('indicator_type')))
        if indicator_data.get('score'):
            if indicator_data.get('score') < 50:
                level = 'safe'
            elif 50 <= indicator_data.get('score') < 80:
                level = 'suspicious'
            else:
                level = 'malicious'
            taxonomies.append(self.build_taxonomy(level, namespace, "Score", indicator_data.get('score')))
        if len(taxonomies) == 0:
            taxonomies.append(self.build_taxonomy(level, namespace, 'Threat', 'Not found'))

        return {"taxonomies": taxonomies}

    def run(
            self
    ):
        try:
            indicator = self.get_param('data', None, 'Data is missing')
            indicator_data = self.investigate(indicator)
            if indicator_data:
                self.report(indicator_data)
        except Exception as e:
            self.error(e)


if __name__ == '__main__':
    C25CortexAnalyzer().run()
