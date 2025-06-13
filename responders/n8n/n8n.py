#!/usr/bin/env python3
from cortexutils.responder import Responder
import requests


class SendToN8NResponder(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.url = self.get_param("config.webhook", None, "n8n webhook URL missing!")


    def run(self):
        Responder.run(self)

        r = requests.post(self.url, json=self.get_data())
        if r.status_code == 200:
            self.report({"Message": "Executed workflow"})
        else:
            self.error(r.status_code)

if __name__ == "__main__":
    SendToN8NResponder().run()

