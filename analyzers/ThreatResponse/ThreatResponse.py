#!/usr/bin/env python3
# encoding: utf-8
import re
from copy import deepcopy
from cortexutils.analyzer import Analyzer
from threatresponse import ThreatResponse


class ThreatResponseAnalyzer(Analyzer):
    """
    Cisco Threat Response analyzer
    """

    def __init__(self):
        Analyzer.__init__(self)
        self.region = self.get_param("config.region").lower()
        self.client_id = self.get_param(
            "config.client_id", None, "No Threat Response client ID given."
        )
        self.client_password = self.get_param(
            "config.client_password", None, "No Threat Response client Password given."
        )
        self.extract_amp_targets = self.get_param("config.extract_amp_targets", False)

        # Validate that the supplied region is valid
        if self.region and self.region not in ("us", "eu", "apjc"):
            self.error(
                "{} is not a valid Threat Response region. Must be 'us', 'eu', or 'apjc'".format(
                    self.region
                )
            )

        # Set region to '' if 'us' was supplied
        if self.region == "us":
            self.region = ""

        # Create Threat Response client
        self.client = ThreatResponse(
            client_id=self.client_id,
            client_password=self.client_password,
            region=self.region,
        )

    def run(self):
        def identify_hash(observable):
            """Validate the provided hash is a supported type
            """
            # RegEx for supported checksum types MD5, SHA1, SHA256
            hash_mapping = {
                re.compile(r"^[A-Za-z0-9]{32}$"): "md5",
                re.compile(r"^[A-Za-z0-9]{40}$"): "sha1",
                re.compile(r"^[A-Za-z0-9]{64}$"): "sha256",
            }

            for expression in hash_mapping:
                if expression.match(observable):
                    return hash_mapping[expression]

        def parse_verdicts(response_json):
            """Parse response from Threat Response and extract verdicts
            """
            verdicts = []
            for module in response_json.get("data", []):
                module_name = module["module"]

                for doc in module.get("data", {}).get("verdicts", {}).get("docs", []):
                    verdicts.append(
                        {
                            "observable_value": doc["observable"]["value"],
                            "observable_type": doc["observable"]["type"],
                            "expiration": doc["valid_time"]["end_time"],
                            "module": module_name,
                            "disposition_name": doc["disposition_name"],
                        }
                    )

            return verdicts

        def parse_targets(response_json):
            """Parse response Threat Response and extract targets
            """
            result = []
            for module in response_json.get("data", []):
                module_name = module["module"]
                module_type = module["module-type"]
                targets = []

                for doc in module.get("data", {}).get("sightings", {}).get("docs", []):

                    for target in doc.get("targets", []):
                        element = deepcopy(target)
                        element.pop("observed_time", None)
                        if element not in targets:
                            targets.append(element)

                if targets:
                    result.append(
                        {
                            "module": module_name,
                            "module_type": module_type,
                            "targets": targets,
                        }
                    )

            return result

        # Map The Hive observable types to Threat Response observable types
        observable_mapping = {
            "domain": "domain",
            "mail": "email",
            "mail_subject": "email_subject",
            "filename": "file_name",
            "fqdn": "domain",
            "hash": None,
            "ip": "ip",
            "url": "url",
        }

        # Map the provided region to the FQDN
        host_mapping = {
            "": "visibility.amp.cisco.com",
            "us": "visibility.amp.cisco.com",
            "eu": "visibility.eu.amp.cisco.com",
            "apjc": "visibility.apjc.amp.cisco.com",
        }

        dataType = self.get_param("dataType")

        # Validate the supplied observable type is supported
        if dataType in observable_mapping.keys():
            observable = self.get_data()  # Get the observable data

            # If the observable type is 'hash' determine which type of hash
            # Threat Response only supports MD5, SHA1, SHA256
            if dataType == "hash":
                hash_type = identify_hash(observable)
                if hash_type:
                    observable_mapping["hash"] = hash_type
                else:
                    self.error(
                        "{} is not a valid MD5, SHA1, or SHA256".format(observable)
                    )

            # Format the payload to be sent to the Threat Response API
            payload = [{"value": observable, "type": observable_mapping[dataType]}]

            # Query Threat Response Enrich API
            response = self.client.enrich.observe.observables(payload)

            # Parse verdicts from response for display
            verdicts = parse_verdicts(response)

            # Parse targets from response for display
            targets = parse_targets(response)

            # Build raw report
            raw_report = {
                "response": response,
                "targets": targets,
                "verdicts": verdicts,
                "host": host_mapping[self.region],
                "observable": observable,
            }

            self.report(raw_report)

        else:
            self.error("Data type {} not supported".format(dataType))

    def summary(self, raw):
        taxonomies = []
        namespace = "TR"

        verdicts = raw.get("verdicts", [])

        # Map Threat Response dispositions to The Hive levels
        level_mapping = {
            "Clean": "safe",
            "Common": "safe",
            "Malicious": "malicious",
            "Suspicious": "suspicious",
            "Unknown": "info",
        }

        for verdict in verdicts:
            disposition_name = verdict.get(
                "disposition_name"
            )  # Clean, Common, Malicious, Suspicious, Unknown
            module = verdict.get("module")

            taxonomies.append(
                self.build_taxonomy(
                    level_mapping[disposition_name], namespace, module, disposition_name
                )
            )

        # Inform if not module returned a verdict
        if len(verdicts) < 1:
            taxonomies.append(
                self.build_taxonomy("info", namespace, "Enrich", "No Verdicts")
            )
            # level, namespace, predicate, value

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []

        if self.extract_amp_targets:
            for module in raw.get("targets", []):
                if module.get("module_type") == "AMPInvestigateModule":
                    for target in module.get("targets", []):
                        for observable in target.get("observables", []):
                            if observable.get("type") == "hostname":
                                hostname = observable.get("value")
                            if observable.get("type") == "amp_computer_guid":
                                guid = observable.get("value")
                                if guid:
                                    tags = []
                                    if hostname:
                                        tags.append("AMP Hostname:{}".format(hostname))
                                        tags.append("AMP GUID")
                                    artifacts.append(
                                        self.build_artifact("other", guid, tags=tags)
                                    )

        return artifacts


if __name__ == "__main__":
    ThreatResponseAnalyzer().run()
