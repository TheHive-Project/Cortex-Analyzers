#!/usr/bin/env python3
import typing as tp

import requests

from cortexutils.analyzer import Analyzer


class EclecticIQAnalyzer(Analyzer):
    """Searches for given Observables in configured EclecticIQ instance.
    All standard Cortex data types are supported."""

    def __init__(self):
        Analyzer.__init__(self)

        self.service = self.get_param("config.service", default="search_observable")

        self.name = self.get_param(
            "config.name", message="No EclecticIQ instance name given."
        )
        self.url = self.get_param("config.url", message="No EclecticIQ url given.")
        self.key = self.get_param("config.key", message="No EclecticIQ api key given.")
        self.data = self.get_param("data", message="Data is missing")

        if self.get_param("config.cert_check", True):
            self.ssl = self.get_param("config.cert_path", True)
        else:
            self.ssl = False

        self.session = requests.Session()
        self.session.verify = self.ssl
        self.session.proxies = self.get_param("config.proxy")
        self.session.headers.update(
            {"Accept": "application/json", "Authorization": f"Bearer {self.key}"}
        )

    def summary(self, raw):
        level = "info"
        namespace = "EIQ"
        predicate = "API"
        found = len(raw["results"].get("entities", []))
        value = f"Found {found} entities" if found > 0 else "Not found"
        taxonomy = self.build_taxonomy(level, namespace, predicate, value)
        return {"taxonomies": [taxonomy]}

    def get_source(self, url):
        response = self.session.get(url)
        return response.json()["data"]["name"]

    @staticmethod
    def get_confidence(data):
        confidence = data.get("confidence", None)
        if isinstance(confidence, dict):
            confidence = confidence.get("value")
        return confidence

    def run(self):
        """
        Query EclecticIQ instance for data by querying observable for
        observable id and then querying entities endpoint for parent entities

        Return dict response to cortex
        """

        results = {
            "name": self.name,
            "url": self.url,
            "obs_value": self.data,
        }
        obs_id = self.add_observable_info(results)
        if not obs_id:
            # exit early for no data
            return self.report({})

        entities_info = self.get_entities_info(obs_id)
        if not entities_info:
            # exit early for no data
            return self.report({})

        results["count"] = entities_info["count"]
        results["entities"] = []
        for entity in entities_info["data"]:
            source_name = self.get_source(entity["sources"][0])
            entity_data = entity.get("data", {})
            results["entities"].append(
                {
                    "id": entity["id"],
                    "title": entity_data.get("title"),
                    "type": entity_data.get("type"),
                    "confidence": self.get_confidence(entity_data),
                    "tags": entity.get("meta", {}).get("tags"),
                    "timestamp": entity.get("meta", {}).get(
                        "estimated_threat_start_time"
                    ),
                    "source_name": source_name,
                }
            )

        self.report({"results": results})

    def add_observable_info(self, results: dict) -> tp.Optional[str]:
        url = self.url + "/api/v2/observables"  # set observable url
        params = {"filter[value]": self.data}  # use data in filter param
        response = self.session.get(url, params=params)
        if not response.json().get("count"):
            return None

        data = response.json()["data"]
        results["obs_type"] = data[0]["type"]
        results["obs_score"] = data[0].get("meta", {}).get("maliciousness")
        return data[0]["id"]

    def get_entities_info(self, obs_id: str) -> tp.Optional[dict]:
        url = self.url + "/api/v2/entities"  # set entity url
        params = {"filter[observables]": obs_id}  # use observable id in filter param

        response = self.session.get(url, params=params)
        response_json = response.json()

        if not response_json.get("count"):
            return None

        return response_json


if __name__ == "__main__":
    EclecticIQAnalyzer().run()
