#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cortexutils.analyzer import Analyzer
from greynoise.api import GreyNoise, APIConfig

def get_ip_tag_names(tags: list) -> list:
    """Get tag names from tags list.

    :type tags: ``list``
    :param tags: list of tags.

    :return: list of tag names.
    :rtype: ``list``
    """
    tag_names = []
    for tag in tags:
        tag_name = tag.get("name")
        tag_names.append(tag_name)

    return tag_names

class GreyNoiseAnalyzer(Analyzer):
    """
    GreyNoise API docs: https://docs.greynoise.io/reference/v3ip#/
    GreyNoise Community API Reference: https://docs.greynoise.io/reference/get_v3-community-ip#/
    """

    def run(self):

        if self.data_type == "ip":
            api_key = self.get_param("config.key", None)
            api_config = APIConfig(
                api_key=api_key,
                timeout=30,
                integration_name="greynoise-cortex-analyzer-v3.2",
            )
            api_client = GreyNoise(api_config)
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
            "suspicious": lambda x: "suspicious",
            "malicious": lambda x: "malicious",
        }

        try:
            taxonomies = []

            scanner_found = raw.get("internet_scanner_intelligence", {}).get("found", False)
            business_service_found = raw.get("business_service_intelligence", {}).get("found", False)
            if scanner_found and not business_service_found:
                #print("scanner_found and not business_service_found")
                tag_names = get_ip_tag_names(raw.get("internet_scanner_intelligence", {}).get("tags", []))
                tag_count = len(tag_names)
                classification = raw.get("internet_scanner_intelligence", {}).get("classification", "unknown")
                actor = raw.get("internet_scanner_intelligence", {}).get("actor", "")

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
            elif business_service_found and not scanner_found:
                #print("business_service_found and not scanner_found")
                trust_level = raw.get("business_service_intelligence", {}).get("trust_level", 0)
                category = raw.get("business_service_intelligence", {}).get("category", "")
                if trust_level == 1:
                    classification = "benign"
                else:
                    classification = "unknown"
                name = raw.get("business_service_intelligence", {}).get("name", "")
                t1_level = classification_level_map.get(classification)(None)
                t1_namespace = "GreyNoise"
                t1_predicate = "classification"
                t1_value = classification
                # print('{}:{} = {} ({})'.format(t1_namespace, t1_predicate, t1_value))
                taxonomies.append(
                    self.build_taxonomy(t1_level, t1_namespace, t1_predicate, t1_value)
                )
                t2_level = classification_level_map.get(classification)(None)
                t2_namespace = "GreyNoise"
                t2_predicate = "Name"
                t2_value = name
                # print('{}:{} = {} ({})'.format(t2_namespace, t2_predicate,
                #                               t2_value, t2_level))
                taxonomies.append(
                    self.build_taxonomy(t2_level, t2_namespace, t2_predicate, t2_value)
                )
                t3_level = classification_level_map.get(classification)(None)
                t3_namespace = "GreyNoise"
                t3_predicate = "Type"
                t3_value = category
                # print('{}:{} = {} ({})'.format(t3_namespace, t3_predicate,
                #                                  t3_value, t3_level))
                taxonomies.append(
                    self.build_taxonomy(t3_level, t3_namespace, t3_predicate, t3_value)
                )
            elif scanner_found and business_service_found:
                #print("scanner_found and business_service_found")
                tag_names = get_ip_tag_names(raw.get("internet_scanner_intelligence", {}).get("tags", []))
                tag_count = len(tag_names)
                classification = raw.get("internet_scanner_intelligence", {}).get("classification", "unknown")
                actor = raw.get("internet_scanner_intelligence", {}).get("actor", "")
                category = raw.get("business_service_intelligence", {}).get("category", "")
                name = raw.get("business_service_intelligence", {}).get("name", "")

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
                t3_level = classification_level_map.get(classification)(None)
                t3_namespace = "GreyNoise"
                t3_predicate = "Name"
                t3_value = name
                # print('{}:{} = {} ({})'.format(t2_namespace, t2_predicate,
                #                               t2_value, t2_level))
                taxonomies.append(
                    self.build_taxonomy(t3_level, t3_namespace, t3_predicate, t3_value)
                )
                t4_level = classification_level_map.get(classification)(None)
                t4_namespace = "GreyNoise"
                t4_predicate = "Type"
                t4_value = category
                # print('{}:{} = {} ({})'.format(t3_namespace, t3_predicate,
                #                                  t3_value, t3_level))
                taxonomies.append(
                    self.build_taxonomy(t4_level, t4_namespace, t4_predicate, t4_value)
                )
            else:
                #print("neither scanner_found nor business_service_found")
                taxonomies.append(
                    self.build_taxonomy(
                        classification_level_map.get("unknown")(None),
                        "GreyNoise",
                        "IP not observed scanning the internet in the last 90 days",
                        False,
                    )
                )

            return {"taxonomies": taxonomies}

        except Exception as e:
            self.error("Summary failed\n{}".format(e.message))


if __name__ == "__main__":
    GreyNoiseAnalyzer().run()
