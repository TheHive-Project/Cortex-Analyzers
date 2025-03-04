#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.responder import Responder

class Test(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.report({"message": "test"})

    def run(self):
        Responder.run(self)

    def operations(self, raw):
        # AddTagToArtifact ({ "type": "AddTagToArtifact", "tag": "tag to add" }): add a tag to the artifact related to the object
        # AddTagToCase ({ "type": "AddTagToCase", "tag": "tag to add" }): add a tag to the case related to the object
        # MarkAlertAsRead: mark the alert related to the object as read
        # AddCustomFields ({"name": "key", "value": "value", "tpe": "type"): add a custom field to the case related to the object
        return [self.build_operation("AddTagToCase", tag="test")]


if __name__ == "__main__":
    Test().run()
