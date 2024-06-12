#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cortexutils.analyzer import Analyzer
from greynoise import GreyNoise


class GreyNoiseAnalyzer(Analyzer):
    """
    GreyNoise API docs: https://developer.greynoise.io/reference#noisecontextip-1
    GreyNoise Community API Reference: https://developer.greynoise.io/reference/community-api
    """

    def run(self):

        if self.data_type == "ip":
            api_key = self.get_param("config.key", None)
            api_type = self.get_param("config.api_type", None)
            if api_type and api_type.lower() == "community":
                api_client = GreyNoise(
                    api_key=api_key,
                    timeout=30,
                    integration_name="greynoise-cortex-analyzer-v3.1",
                    offering="community",
                )
            else:
                api_client = GreyNoise(
                    api_key=api_key,
                    timeout=30,
                    integration_name="greynoise-cortex-analyzer-v3.1",
                )
            try:
                self.report(api_client.ip(self.get_data()))
            except Exception as e:
                self.error("Unable to query GreyNoise API\n{}".format(e))
        else:
            self.notSupported()

    def summary(self, raw):
        """
        Return two taxonomies

        Examples:

        Input
        {
            "seen": True,
            "actor": "SCANNER1",
            "classification": "benign",
            "tags": ['a', 'b', 'c']
        }
        Output
        GreyNoise:tags = 3 (Safe)
        GreyNoise:actor = SCANNER1 (Safe)

        Input
        {
            "seen": True,
            "actor": "SCANNER1",
            "classification": "unknown",
            "tags": ['a', 'b', 'c']
        }
        Output
        GreyNoise:tags = 3 (Suspicious)
        GreyNoise:classification = unknown (Info)

        Input
        {
            "seen": True,
            "actor": "SCANNER1",
            "classification": "unknown",
            "tags": ['a', 'b']
        }
        Output
        GreyNoise:tags = 2 (Info)
        GreyNoise:classification = unknown (Info)

        Input
        {
            "seen": True,
            "actor": "SCANNER1",
            "classification": "malicious",
            "tags": ['a', 'b', 'c']
        }
        Output
        GreyNoise:tags = 3 (Malicious)
        GreyNoise:classification = malicious (Malicious)

        Input
        {
            "seen": "False"
        }
        Output
        GreyNoise:Seen last 60 days = False (Info)
        """

        classification_level_map = {
            "benign": lambda x: "safe",
            "unknown": lambda tag_count: "info"
            if (not tag_count) or (tag_count <= 2)
            else "suspicious",
            "malicious": lambda x: "malicious",
        }

        try:
            taxonomies = []

            seen = raw.get("seen", False)
            noise = raw.get("noise", False)
            riot = raw.get("riot", False)
            if seen:
                tag_count = len(raw.get("tags", []))
                classification = raw.get("classification", "unknown")
                actor = raw.get("actor")

                t1_level = classification_level_map.get(classification)(tag_count)
                t1_namespace = "GreyNoise"
                t1_predicate = "tags"
                t1_value = tag_count
                # print('{}:{} = {} ({})'.format(t1_namespace, t1_predicate,
                #                               t1_value, t1_level))
                taxonomies.append(
                    self.build_taxonomy(t1_level, t1_namespace, t1_predicate, t1_value)
                )

                t2_level = classification_level_map.get(classification)(None)
                t2_namespace = "GreyNoise"
                t2_predicate = (
                    "actor" if classification == "benign" else "classification"
                )
                t2_value = actor if classification == "benign" else classification
                # print('{}:{} = {} ({})'.format(t2_namespace, t2_predicate,
                #                               t2_value, t2_level))
                taxonomies.append(
                    self.build_taxonomy(t2_level, t2_namespace, t2_predicate, t2_value)
                )
            elif noise or riot:
                classification = raw.get("classification", "unknown")
                name = raw.get("name")
                t1_level = classification_level_map.get(classification)(None)
                t1_namespace = "GreyNoise Community"
                t1_predicate = "classification"
                t1_value = classification
                # print('{}:{} = {} ({})'.format(t1_namespace, t1_predicate, t1_value))
                taxonomies.append(
                    self.build_taxonomy(t1_level, t1_namespace, t1_predicate, t1_value)
                )
                t2_level = classification_level_map.get(classification)(None)
                t2_namespace = "GreyNoise Community"
                t2_predicate = "Name"
                t2_value = name
                # print('{}:{} = {} ({})'.format(t2_namespace, t2_predicate,
                #                               t2_value, t2_level))
                taxonomies.append(
                    self.build_taxonomy(t2_level, t2_namespace, t2_predicate, t2_value)
                )
                t3_level = classification_level_map.get(classification)(None)
                t3_namespace = "GreyNoise Community"
                t3_predicate = "Type"
                t3_value = "Benign Service" if riot else "Internet Noise"
                # print('{}:{} = {} ({})'.format(t3_namespace, t3_predicate,
                #                                  t3_value, t3_level))
                taxonomies.append(
                    self.build_taxonomy(t3_level, t3_namespace, t3_predicate, t3_value)
                )
            else:
                taxonomies.append(
                    self.build_taxonomy(
                        classification_level_map.get("unknown")(None),
                        "GreyNoise",
                        "IP observed scanning the internet in the last 90 days",
                        False,
                    )
                )

            return {"taxonomies": taxonomies}

        except Exception as e:
            self.error("Summary failed\n{}".format(e.message))


if __name__ == "__main__":
    GreyNoiseAnalyzer().run()
