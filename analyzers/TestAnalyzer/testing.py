#!/usr/bin/env python3
# encoding: utf-8

import hashlib
import random

from cortexutils.analyzer import Analyzer

MAX_ARTIFACTS = 10_000
ARTIFACT_TYPES = ["ip", "domain", "url", "hash", "mail"]
WORDS = [
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
    "india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
    "quebec", "romeo", "sierra", "tango", "uniform", "victor", "whiskey",
    "xray", "yankee", "zulu",
]


class TestAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.some_string = self.get_param("config.some_string", None)
        self.some_list = self.get_param("config.some_list", ["item1", "item2", "item3"])
        self.some_number = self.get_param("config.some_number", 1)
        self.throw_error = self.get_param("config.throw_error", False)
        self.artifact_count = self.get_param("config.artifact_count", 1)
        self.service = self.get_param(
            "config.service", None, "Service parameter is missing"
        )

    def run(self):
        try:
            if self.throw_error:
                error_message = "this is an error string: throw_error boolean is set to True in Cortex"
                self.error(error_message)
            data = self.get_data()
            # data = self.get_param("data", None, "Data is missing")
            datatype = self.data_type

            if self.service == "echo":
                everything = {
                    # Observable metadata
                    # "_id": self.get_param("_id", None),               ## Not supported / Not in input
                    # "_type": self.get_param("_type", None),           ## Not supported / Not in input
                    # "_createdBy": self.get_param("_createdBy", None), ## Not supported / Not in input
                    # "_updatedBy": self.get_param("_updatedBy", None), ## Not supported / Not in input
                    # "_createdAt": self.get_param("_createdAt", None), ## Not supported / Not in input
                    # "_updatedAt": self.get_param("_updatedAt", None), ## Not supported / Not in input

                    # Core observable
                    "dataType": self.get_param("dataType", None),
                    "data": self.get_param("data", None),

                    # Dates
                    # "startDate": self.get_param("startDate", None),   ## Not supported / Not in input

                    # TLP / PAP
                    "tlp": self.get_param("tlp", None),
                    # "tlpLabel": self.get_param("tlpLabel", None),    ## Not supported / Not in input
                    "pap": self.get_param("pap", None),
                    # "papLabel": self.get_param("papLabel", None),    ## Not supported / Not in input

                    # Tags / IOC / Sighted
                    # "tags": self.get_param("tags", None),            ## Not supported / Not in input
                    # "ioc": self.get_param("ioc", None),              ## Not supported / Not in input
                    # "sighted": self.get_param("sighted", None),      ## Not supported / Not in input
                    # "sightedAt": self.get_param("sightedAt", None),  ## Not supported / Not in input
                    # "ignoreSimilarity": self.get_param("ignoreSimilarity", None), ## Not supported / Not in input

                    # Reports
                    # "reports": self.get_param("reports", None),      ## Not supported / Not in input

                    # Message
                    "message": self.get_param("message", None), # Represents case ID!

                    # Extra data
                    # "extraData": self.get_param("extraData", None),  ## Not supported / Not in input

                    # File / attachment (if applicable)
                    "file": self.get_param("file", None),            ## Not in input (null unless dataType=="file")
                    "attachment": self.get_param("attachment", None),## Not supported / Not in input

                    # Job parameters & analyzer config blocks
                    "parameters": self.get_param("parameters", {}),
                    "config": self.get_param("config", {}),

                    # Proxy (if passed)
                    "proxy": self.get_param("proxy", {}),
                }
                result = everything

            elif self.service == "testing":
                # result = {"data": data, "dataType": datatype, "arrayExample": ["A", "B", "C"], "tableExample": {"colA": "row A value", "colB": "row B value", "colC": "row C value",}}

                # Unicode test data
                unicode_test_string = "こんにちは, 你好, 안녕하세요, 😀, 💻, π, ∑, ∞, « Bonjour, comment ça va ? »"
                unicode_table_example = {
                    "colA": "Row A: こんにちは (Hello in Japanese)",
                    "colB": "Row B: 你好 (Hello in Chinese)",
                    "colC": "Row C: 😀 (Smiley emoji)",
                    "colD": "«Row D: Bonjour, comment ça va ? Très bien. » (Hello, how are you? Doing very well. in French)",
                }

                result = {
                    "data": data,
                    "dataType": datatype,
                    "arrayExample": ["A", "B", "C", "Δ", "Ж", "Ω", "💡"],
                    "tableExample": unicode_table_example,
                    "unicodeTest": unicode_test_string,
                }

            else:
                self.error(f"Unknown service: {self.service}")

            self.report(result)
        except Exception as e:
            self.error(f"Unhandled exception: {e}")

    @staticmethod
    def _artifact_value(data_type, index, rng):
        word = WORDS[index % len(WORDS)]
        domain = f"sample-{index}-{word}.example"
        if data_type == "ip":
            return f"10.{(index >> 16) & 255}.{(index >> 8) & 255}.{index & 255}"
        if data_type == "domain":
            return domain
        if data_type == "url":
            return f"https://{domain}/{word}/{rng.getrandbits(32)}"
        if data_type == "mail":
            return f"user-{index}@{domain}"
        digest = hashlib.sha256(f"sample-{index}-{rng.getrandbits(64)}".encode()).hexdigest()
        return digest[: (32, 40, 64)[index % 3]]

    def summary(self, raw):
        taxonomies = []
        namespace = "testing"
        predicate = self.data_type
        value = "None"

        if self.service == "testing":
            # safe, info, suspicious, malicious
            for level in ["info", "safe", "suspicious", "malicious"]:
                taxonomies.append(
                    self.build_taxonomy(level, namespace, predicate, value)
                )
        return {"taxonomies": taxonomies}

    def operations(self, raw):
        operations = []
        ## For reference only
        # case class AddTagToCase(tag: String)                                  extends ActionOperation
        # case class AddTagToArtifact(tag: String)                              extends ActionOperation
        # case class CreateTask(title: String, description: String)             extends ActionOperation
        # case class AddCustomFields(name: String, tpe: String, value: JsValue) extends ActionOperation
        # case class CloseTask()                                                extends ActionOperation
        # case class MarkAlertAsRead()                                          extends ActionOperation
        # case class AddLogToTask(content: String, owner: Option[String])       extends ActionOperation
        # case class AddTagToAlert(tag: String)                                 extends ActionOperation
        # case class AddArtifactToCase(
        #     data: String,
        #     dataType: String,
        #     message: String,
        #     tlp: Option[Int],
        #     ioc: Option[Boolean],
        #     sighted: Option[Boolean],
        #     ignoreSimilarity: Option[Boolean],
        #     tags: Option[Seq[String]]
        # )                                    extends ActionOperation
        # case class AssignCase(owner: String) extends ActionOperation
        if self.service == "testing":
            operations.append(self.build_operation("AddTagToArtifact", tag="test"))
        return operations

    def artifacts(self, raw):
        artifacts = []
        if self.service == "testing":
            try:
                count = min(max(int(self.artifact_count), 0), MAX_ARTIFACTS)
            except (TypeError, ValueError):
                count = 1
            rng = random.Random(42)
            for index in range(count):
                data_type = ARTIFACT_TYPES[index % len(ARTIFACT_TYPES)]
                value = self._artifact_value(data_type, index, rng)
                artifacts.append(self.build_artifact(data_type, value, tags=["test"]))
        return artifacts


if __name__ == "__main__":
    TestAnalyzer().run()
