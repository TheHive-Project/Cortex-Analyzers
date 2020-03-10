#!/usr/bin/env python3
# encoding: utf-8

from domaintools.exceptions import NotFoundException
from domaintools.exceptions import NotAuthorizedException
from domaintools.exceptions import ServiceUnavailableException

from domaintools import API

from cortexutils.analyzer import Analyzer
from datetime import datetime


class DomainToolsAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            "config.service", None, "Service parameter is missing"
        )
        self.raw = ""
        self.pivot_count_threshold = int(self.get_param("config.pivot_count_threshold"))

    @staticmethod
    def get_domain_age(create_date):
        """
        Finds how many days old a domain is given a start date.
        Args:
            create_date: Date in the form of %Y-%m-%d'

        Returns: Number of days
        """
        time_diff = datetime.now() - datetime.strptime(create_date, "%Y-%m-%d")
        return time_diff.days

    @staticmethod
    def get_threat_level(risk_score):
        level = "info"
        if risk_score <= 65:
            level = "safe"
        elif 65 < risk_score <= 80:
            level = "suspicious"
        elif risk_score > 80:
            level = "malicious"
        return level

    @staticmethod
    def get_threat_level_class(risk_score):
        level = ""
        if risk_score <= 65:
            level = "label-success"
        elif 65 < risk_score <= 80:
            level = "label-warning"
        elif risk_score > 80:
            level = "label-danger"
        return level

    def add_pivot_class(self, data_obj):
        """
        Does a deep dive through a data object to check count vs pivot threshold to add class to DOM element.
        Args:
            data_obj: Either a list or dict that needs to check pivot count
        """
        if isinstance(data_obj, dict) and len(data_obj):
            for k, v in data_obj.items():
                if isinstance(data_obj[k], dict) or isinstance(data_obj[k], list):
                    self.add_pivot_class(data_obj[k])
            if "count" in data_obj and (
                0 < data_obj["count"] < self.pivot_count_threshold
            ):
                data_obj["class"] = "label-danger"
            elif "count" in data_obj and data_obj["count"] == 0:
                del data_obj["count"]
            elif (
                "count" in data_obj
                and "class" not in data_obj
                and data_obj["count"] != 0
            ):
                data_obj["class"] = "label-info"

        elif isinstance(data_obj, list) and len(data_obj):
            for index, item in enumerate(data_obj):
                self.add_pivot_class(item)

    @staticmethod
    def get_threat_component(components, threat_type):
        """
        Gets a certain threat component out a list of components
        Args:
            components: List of threat components
            threat_type: Type of threat we are looking for

        Returns: Either the component that we asked for or None
        """
        for component in components:
            if component.get("name") == threat_type:
                return component
        else:
            return None

    def format_single_domain(self, domain_data):
        domain_data["last_enriched"] = datetime.now().date().strftime("%m-%d-%Y")
        if isinstance(domain_data["website_response"], dict):
            domain_data["website_response"] = domain_data["website_response"].get(
                "value", ""
            )
        # Threat Components Flatten
        domain_risk = domain_data.get("domain_risk", {})

        overall_risk_score = domain_risk.get("risk_score", 0)
        domain_risk["overall"] = {
            "value": overall_risk_score,
            "class": DomainToolsAnalyzer.get_threat_level_class(overall_risk_score),
        }
        risk_components = domain_risk.get("components", {})
        if risk_components:
            proximity_data = DomainToolsAnalyzer.get_threat_component(
                risk_components, "proximity"
            )
            blacklist_data = DomainToolsAnalyzer.get_threat_component(
                risk_components, "blacklist"
            )
            domain_risk["proximity"] = {"value": 0}
            if proximity_data:
                domain_risk["proximity"]["value"] = proximity_data.get("risk_score", 0)
            elif blacklist_data:
                domain_risk["proximity"]["value"] = blacklist_data.get("risk_score", 0)
            domain_risk["proximity"][
                "class"
            ] = DomainToolsAnalyzer.get_threat_level_class(
                domain_risk["proximity"]["value"]
            )
            threat_profile_data = DomainToolsAnalyzer.get_threat_component(
                risk_components, "threat_profile"
            )
            if threat_profile_data:
                domain_risk["tp"] = {}
                domain_risk["tp"]["value"] = threat_profile_data.get("risk_score", 0)
                domain_risk["tp"]["class"] = DomainToolsAnalyzer.get_threat_level_class(
                    domain_risk["tp"]["value"]
                )
                domain_risk["tp"]["threats"] = threat_profile_data.get("threats", [])
                domain_risk["tp"]["evidence"] = threat_profile_data.get("evidence", [])
            threat_profile_malware_data = DomainToolsAnalyzer.get_threat_component(
                risk_components, "threat_profile_malware"
            )
            if threat_profile_malware_data:
                domain_risk["tpm"] = {}
                domain_risk["tpm"]["value"] = threat_profile_malware_data.get(
                    "risk_score", 0
                )
                domain_risk["tpm"][
                    "class"
                ] = DomainToolsAnalyzer.get_threat_level_class(
                    domain_risk["tpm"]["value"]
                )
            threat_profile_phishing_data = DomainToolsAnalyzer.get_threat_component(
                risk_components, "threat_profile_phishing"
            )
            if threat_profile_phishing_data:
                domain_risk["tpp"] = {}
                domain_risk["tpp"]["value"] = threat_profile_phishing_data.get(
                    "risk_score", 0
                )
                domain_risk["tpp"][
                    "class"
                ] = DomainToolsAnalyzer.get_threat_level_class(
                    domain_risk["tpp"]["value"]
                )
            threat_profile_spam_data = DomainToolsAnalyzer.get_threat_component(
                risk_components, "threat_profile_spam"
            )
            if threat_profile_spam_data:
                domain_risk["tps"] = {}
                domain_risk["tps"]["value"] = threat_profile_spam_data.get(
                    "risk_score", 0
                )
                domain_risk["tps"][
                    "class"
                ] = DomainToolsAnalyzer.get_threat_level_class(
                    domain_risk["tps"]["value"]
                )

        # Contacts Flatten
        domain_data["types"] = [
            "registrant_contact",
            "admin_contact",
            "technical_contact",
            "billing_contact",
        ]
        domain_data["contacts"] = []
        for c in domain_data["types"]:
            split_type = c.split("_")
            domain_data[c]["type"] = "{} Contact".format(split_type[0].capitalize())
            domain_data["contacts"].append(domain_data[c])

        self.add_pivot_class(domain_data)
        return domain_data

    @staticmethod
    def format_pivot_domains(domains, artifact_type, artifact_data):
        result = {
            "last_enriched": datetime.now().date().strftime("%m-%d-%Y"),
            "pivot_artifact": "{} = {}".format(artifact_type.upper(), artifact_data),
            "average_risk_score": 0,
        }
        total_risk_score = 0
        sorted_domains = sorted(
            domains,
            key=lambda d: (
                d.get("domain_risk", 0).get("risk_score", 0),
                d.get("domain"),
            ),
            reverse=True,
        )
        result_domains = []
        for domain in sorted_domains:
            total_risk_score += domain.get("domain_risk", 0).get("risk_score", 0)
            temp_dict = {"domain": domain.get("domain")}
            risk_score = domain.get("domain_risk", 0).get("risk_score", 0)
            temp_dict["domain_risk"] = {
                "class": DomainToolsAnalyzer.get_threat_level_class(risk_score),
                "risk_score": risk_score,
            }
            create_date = domain.get("create_date", {}).get("value", "")
            if create_date:
                temp_dict["domain_age"] = DomainToolsAnalyzer.get_domain_age(
                    create_date
                )
            else:
                temp_dict["domain_age"] = 0
            result_domains.append(temp_dict)
        result["results"] = result_domains
        if len(result_domains):
            result["average_risk_score"] = total_risk_score // len(result_domains)
        return result

    def domaintools(self, data):
        response = None
        api = API(self.get_param("config.username"), self.get_param("config.key"))

        APP_PARAMETERS = {"app_partner": "cortex", "app_name": "Iris", "app_version": 1}

        if self.service == "investigate-domain" and self.data_type in ["domain"]:
            response = api.iris_investigate(data, **APP_PARAMETERS).response()
            if response["results_count"]:
                response = self.format_single_domain(response.get("results")[0])

        elif self.service == "pivot" and self.data_type in ["hash", "ip", "mail"]:
            iris_investigate_args_map = {
                "ip": "ip",
                "mail": "email",
                "hash": "ssl_hash",
            }
            APP_PARAMETERS[iris_investigate_args_map[self.data_type]] = data
            response = api.iris_investigate(**APP_PARAMETERS).response()
            response = DomainToolsAnalyzer.format_pivot_domains(
                response.get("results"), iris_investigate_args_map[self.data_type], data
            )

        return response

    def summary(self, raw):
        self.raw = raw
        r = {"service": self.service, "dataType": self.data_type}

        taxonomies = []

        # Prepare predicate and value for each service
        if r["service"] == "investigate-domain":
            if "risk_score" in raw["domain_risk"]:
                risk_score = raw["domain_risk"]["overall"]["value"]
                level = self.get_threat_level(risk_score)
                taxonomies.append(
                    self.build_taxonomy(
                        level, "DT", "Risk Score", "{}".format(risk_score)
                    )
                )
            else:
                taxonomies.append(
                    self.build_taxonomy("info", "DT", "Risk Score", "No Risk Score")
                )

            if "tp" in raw["domain_risk"]:
                risk_score = raw["domain_risk"]["tp"]["value"]
                level = self.get_threat_level(risk_score)
                taxonomies.append(
                    self.build_taxonomy(
                        level, "DT", "Threat Profile Score", "{}".format(risk_score)
                    )
                )
                evidence = ",".join(raw["domain_risk"]["tp"]["evidence"])
                if evidence:
                    taxonomies.append(
                        self.build_taxonomy(
                            "info", "DT", "Evidence", "{}".format(evidence)
                        )
                    )
            else:
                taxonomies.append(
                    self.build_taxonomy(
                        "info", "DT", "Threat Profile Score", "No Threat Profile Score"
                    )
                )
            tags = ",".join([t["label"] for t in raw.get("tags", [])])
            if tags:
                taxonomies.append(
                    self.build_taxonomy("info", "DT", "IrisTags", "{}".format(tags))
                )

        elif r["service"] == "pivot":
            taxonomies.append(self.build_taxonomy("info", "DT", "Pivots", "Pivots"))

        result = {"taxonomies": taxonomies}
        return result

    def run(self):
        data = self.get_data()

        try:
            r = self.domaintools(data)

            if "error" in r and "message" in r["error"]:
                # noinspection PyTypeChecker
                self.error(r["error"]["message"])
            else:
                self.report(r)

        except NotFoundException:
            self.error(self.data_type.capitalize() + " not found")
        except NotAuthorizedException:
            self.error("An authorization error occurred")
        except ServiceUnavailableException:
            self.error("DomainTools Service is currenlty unavailable")
        except Exception as e:
            self.unexpectedError(e)


if __name__ == "__main__":
    DomainToolsAnalyzer().run()
