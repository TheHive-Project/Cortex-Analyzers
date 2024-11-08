#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
from typing import Optional

import requests
import traceback
import uuid

from cortexutils.responder import Responder


SEVERITY_MAP = {
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
}
CONFIDENCE_MAP = {1: "Low", 2: "Medium", 3: "High", 4: "High"}
DEFAULT_TAGS = ["Hive", "Cortex", "Responder"]
TLP_PAP_MAP = {
    0: "WHITE",
    1: "GREEN",
    2: "AMBER",
    3: "RED",
}


class EclecticIQIndicator(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.eiq_host_url = self.get_param(
            "config.eiq_host_url",
            None,
            "EclecticIQ Intelligence Center host URL (e.g.:https://demo.eclecticiq.com)",
        )
        self.apikey = self.get_param(
            "config.eiq_api_key", None, "EclecticIQ Intelligence Center API key missing"
        )
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.apikey}",
        }
        self.group_name = self.get_param(
            "config.group_name",
            "Testing Group",
            "EclecticIQ Intelligence Center Group Name (e.g.:Testing Group)",
        )

    @staticmethod
    def convert_eiq_observable_type(value):
        ioc_types = {
            "address": "address",
            "asn": "asn",
            "cve": "cve",
            "domain": "domain",
            "email": "email",
            "file": "file",
            "filename": "file",
            "fqdn": "host",
            "hash": "hash-sha256",
            "host": "host",
            "imphash": "hash-imphash",
            "ip": "ipv4",
            "ipv4": "ipv4",
            "ipv4-addr": "ipv4",
            "ipv4-net": "ipv4-cidr",
            "ipv6": "ipv6",
            "ipv6-addr": "ipv6",
            "ipv6-net": "ipv6-cidr",
            "mac": "mac-48",
            "mail": "email",
            "mail_subject": "email-subject",
            "md5": "hash-md5",
            "mutex": "mutex",
            "organization": "organization",
            "phone_number": "telephone",
            "registry": "registrar",
            "sha256": "hash-sha256",
            "sha384": "hash-sha384",
            "sha512": "hash-sha512",
            "uri": "uri",
            "uri_path": "uri",
            "url": "uri",
            "user-agent": "user-agent",
        }
        return ioc_types.get(value.lower())

    @staticmethod
    def format_time(value):
        if value:
            return datetime.fromtimestamp(value // 1000).isoformat()
        return None

    @staticmethod
    def get_max(value1: Optional[int], value2: Optional[int]) -> Optional[int]:
        if value1 and value2:
            return max(value2, value1)
        return value1 or value2

    def make_report(self, case_data, source_id):
        desc_fields = [
            ("title", "Case Title"),
            ("description", "Case Description"),
            ("summary", "Case Summary"),
        ]
        description = ""
        for field, title in desc_fields:
            if case_data.get(field):
                description += f"<p><strong>{title}:</strong> {case_data[field]}</p>"

        tags = DEFAULT_TAGS.copy() + case_data.get("tags", [])
        confidence = CONFIDENCE_MAP.get(case_data.get("severity"))
        case_data["severity"] = SEVERITY_MAP.get(case_data.get("severity"))

        case_tag_fields = [
            ("caseId", "Case ID"),
            ("severity", "Severity"),
            ("impactStatus", "Impact Status"),
            ("resolutionStatus", "Resolution Status"),
            ("status", "Status"),
            ("stage", "Stage"),
            ("owner", "Owner"),
        ]
        for tag_field, title in case_tag_fields:
            value = case_data.get(tag_field)
            if value:
                tags.append(f"{title}: {value}")
                description += f"<p><strong>{title}:</strong> {value}</p>"

        # PROCESS TLP
        case_tlp = case_data.get("tlp", None)
        if case_tlp and TLP_PAP_MAP.get(case_tlp):
            case_tlp = TLP_PAP_MAP[case_tlp]

        # PROCESS PAP
        case_pap = case_data.get("pap", None)
        if case_pap and TLP_PAP_MAP.get(case_pap):
            tags.append(f"PAP: {TLP_PAP_MAP[case_pap]}")

        # deduplicate tags
        tags = list(set(tags))

        _id = "{{https://thehive-project.org}}report-{}".format(
            str(uuid.uuid5(uuid.NAMESPACE_X500, case_data.get("id")))
        )

        report = {
            "data": {
                "id": _id,
                "title": f"{case_data.get('title')} - {case_data.get('caseId')}",
                "description": description,
                "type": "report",
            },
            "meta": {
                "estimated_observed_time": self.format_time(
                    case_data.get("updatedAt", None)
                ),
                "estimated_threat_start_time": self.format_time(
                    case_data.get("startDate", None)
                ),
                "tags": tags,
                "tlp_color": case_tlp,
            },
            "sources": [{"source_id": source_id}],
        }

        if confidence:
            report["data"]["confidence"] = dict(type="confidence", value=confidence)
        return report

    def make_indicator(self, hive_data, source_id):
        if not self.convert_eiq_observable_type(hive_data.get("dataType")):
            self.error("Unsupported IOC type")
            return None

        ioc_value = hive_data.get("data", None)
        description = ""
        tags = DEFAULT_TAGS.copy() + hive_data.get("tags", [])

        observable_type = hive_data.get("_type", None)
        if observable_type is not None:
            tags.append(observable_type)
            description += f"<p><strong>Type:</strong> {observable_type}</p>"

        observable_id = hive_data.get("id", None)
        if observable_id is not None:
            tags.append("Observable ID: {}".format(observable_id))
            description += f"<p><strong>Observable ID:</strong> {observable_id}</p>"

        sighted = hive_data.get("sighted", None)
        if sighted is True:
            tags.append("Sighted")
            description += f"<p><strong>Sighted:</strong> True</p>"

        # PROCESS TLP
        tlp = hive_data.get("tlp", None)
        tlp_color = TLP_PAP_MAP.get(tlp, None) if tlp else None

        # PROCESS PAP
        pap = hive_data.get("pap", None)
        if pap and TLP_PAP_MAP.get(pap):
            tags.append(f"PAP: {TLP_PAP_MAP[pap]}")

        # deduplicate tags
        tags = list(set(tags))

        _id = "{{https://thehive-project.org}}indicator-{}".format(
            str(uuid.uuid5(uuid.NAMESPACE_X500, hive_data["id"]))
        )

        indicator = {
            "data": {
                "id": _id,
                "title": ioc_value,  # use the main value as the title
                "description": description,  # use hive description fields combined
                "type": "indicator",
                "extracts": [
                    {
                        "kind": self.convert_eiq_observable_type(
                            hive_data.get("dataType")
                        ),
                        "value": ioc_value,
                    }
                ],
            },
            "meta": {
                "estimated_observed_time": self.format_time(
                    hive_data.get("updatedAt", None)
                ),
                "estimated_threat_start_time": self.format_time(
                    hive_data.get("startDate", None)
                ),
                "tags": tags,
                "tlp_color": tlp_color,
            },
            "sources": [{"source_id": source_id}],
        }
        return indicator

    def get_group_source_id(self):
        response = requests.get(
            self.eiq_host_url + "/private/groups/",
            params=f"filter[name]={self.group_name}",
            headers=self.headers,
        )
        if response.status_code != 200:
            return None
        return response.json()["data"][0]["source"]

    def create_relation(self, entity_dict, source_id):
        report_id = entity_dict.get("report")
        indicator_id = entity_dict.get("indicator")
        if not report_id or not indicator_id:
            return None

        relation_id = str(uuid.uuid5(uuid.NAMESPACE_X500, f"{report_id}-{indicator_id}"))
        relationship = {
            "data": [
                {
                    "id": relation_id,
                    "data": {
                        "source": report_id,
                        "key": "reports",
                        "target": indicator_id,
                    },
                    "sources": [source_id],
                }
            ]
        }

        response = requests.put(
            self.eiq_host_url + "/api/v2/relationships",
            json=relationship,
            headers=self.headers,
        )
        return response

    def run(self):
        try:
            Responder.run(self)

            hive_data = self.get_param("data")
            _type = hive_data.get("_type")
            if _type not in ["case", "case_artifact"]:
                self.error("Responder not supported")
                # FIXME: should we return None here?
            case_data = hive_data if _type == "case" else hive_data.get("case")

            source_id = self.get_group_source_id()
            if not source_id:
                self.error("Invalid Group name")
                return

            report = self.make_report(case_data, source_id)

            indicator = None
            if _type == "case_artifact":
                indicator = self.make_indicator(hive_data, source_id)
                if not indicator:
                    self.error("Unsupported IOC type")
                    return

            entities = self.submit_entities(report, indicator)
            if not entities:
                return
            entity_ids = {
                data["data"]["type"]: data["id"] for data in entities.get("data", [])
            }

            relation_response = self.create_relation(entity_ids, source_id)
            if relation_response and relation_response.status_code not in [200, 201]:
                self.error(
                    f"While making the relationship, "
                    f"receiving status: {relation_response.status_code}"
                )
                return

            self.report_result(entity_ids)
        except Exception as ex:
            self.error("Error: {}: ex: {}".format(traceback.format_exc(), ex))

    def submit_entities(self, report: dict, indicator: dict) -> Optional[dict]:
        data = []
        report and data.append(report)
        indicator and data.append(indicator)
        # case data contains parent case information
        json_data = dict(data=data)
        response = requests.put(
            self.eiq_host_url + "/api/v2/entities",
            json=json_data,
            headers=self.headers,
        )
        if response.status_code not in [200, 201]:
            self.error(f"While making the call, receiving {response.status_code}")
            return None

        return response.json()

    def report_result(self, entity_ids: dict) -> None:
        result = {"message": "Submitted to EclecticIQ Intelligence Center"}
        if entity_ids.get("report"):
            result["report_platform_link"] = (
                f"{self.eiq_host_url}/entity/{entity_ids.get('report')}"
            )

        if entity_ids.get("indicator"):
            result["indicator_platform_link"] = (
                f"{self.eiq_host_url}/entity/{entity_ids.get('indicator')}"
            )
        self.report(result)

    def operations(self, raw):
        return [
            self.build_operation("AddTagToArtifact", tag="EclecticIQ:Indicator Created")
        ]


if __name__ == "__main__":
    EclecticIQIndicator().run()
