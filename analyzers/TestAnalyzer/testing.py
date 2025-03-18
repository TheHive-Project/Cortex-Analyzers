#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer

class TestAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.some_string = self.get_param(
            "config.some_string", None, "some_string parameter is missing"
        )
        self.some_list = self.get_param(
            "config.some_list", ["item1", "item2", "item3"], "some_list parameter is missing"
        )
        self.some_number = self.get_param(
            "config.some_number", 1, "some_number parameter is missing"
        )
        self.throw_error = self.get_param(
            "config.throw_error", False, "throw_error parameter is missing"
        )
        
    def run(self):
        if self.throw_error:
            error_message = "this is an error string: throw_error boolean is set to True in Cortex"
            self.error(error_message)
        data = self.get_data()
        #data = self.get_param("data", None, "Data is missing")
        datatype = self.data_type

        #result = {"data": data, "dataType": datatype, "arrayExample": ["A", "B", "C"], "tableExample": {"colA": "row A value", "colB": "row B value", "colC": "row C value",}}
    
        # Unicode test data
        unicode_test_string = "こんにちは, 你好, 안녕하세요, 😀, 💻, π, ∑, ∞, « Bonjour, comment ça va ? »"
        unicode_table_example = {
            "colA": "Row A: こんにちは (Hello in Japanese)", 
            "colB": "Row B: 你好 (Hello in Chinese)", 
            "colC": "Row C: 😀 (Smiley emoji)",
            "colD": "«Row D: Bonjour, comment ça va ? Très bien. » (Hello, how are you? Doing very well. in French)"
        }
    
        result = {
            "data": data, 
            "dataType": datatype, 
            "arrayExample": ["A", "B", "C", "Δ", "Ж", "Ω", "💡"],
            "tableExample": unicode_table_example,
            "unicodeTest": unicode_test_string
        }
    
        self.report(result)
        
    def summary(self, raw):
        taxonomies = []
        namespace = "testing"
        predicate = self.data_type
        value = "None"
        
        # safe, info, suspicious, malicious
        for level in ["info", "safe", "suspicious", "malicious"]:
            taxonomies.append(
                self.build_taxonomy(
                    level, namespace, predicate, value)
            )
        
        return {"taxonomies": taxonomies}

    def operations(self, raw):
        operations = []
        operations.append(self.build_operation('AddTagToArtifact', tag="test"))
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
        return operations

    def artifacts(self, raw):
        artifacts = []
        data_type = "ip"
        value = "8.8.8.8"
        extra_args = {
            "tags": ["test"]
        }
        artifacts.append(self.build_artifact(data_type, value, **extra_args))
        return artifacts


if __name__ == "__main__":
    TestAnalyzer().run()
