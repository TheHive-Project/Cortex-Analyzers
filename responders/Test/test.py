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
        return [self.build_operation("AddTagToCase", tag="test")]


if __name__ == "__main__":
    Test().run()
