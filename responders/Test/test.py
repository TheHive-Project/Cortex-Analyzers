#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.responder import Responder

class Test(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.service = self.get_param("config.service", None, "Service parameter is missing.")

    def run(self):
        Responder.run(self)
        if self.service == "test":
            self.report({"message": "test"})
        elif self.service == "echo":
            self.report(self.get_param("data"))
            
    def operations(self, raw):
        artifacts = []
        # AddTagToArtifact ({ "type": "AddTagToArtifact", "tag": "tag to add" }): add a tag to the artifact related to the object
        # AddTagToCase ({ "type": "AddTagToCase", "tag": "tag to add" }): add a tag to the case related to the object
        # MarkAlertAsRead: mark the alert related to the object as read
        # AddCustomFields ({"name": "key", "value": "value", "tpe": "type"): add a custom field to the case related to the object
        if self.service == "test":
            artifacts.append(self.build_operation("AddTagToCase", tag="test"))
        return artifacts


if __name__ == "__main__":
    Test().run()
