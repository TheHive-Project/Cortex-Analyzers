#!/usr/bin/env python3
from cortexutils.responder import Responder
import requests

class Shuffle(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.api_key = self.get_param("config.api_key", "")
        self.url = self.get_param("config.url", "")
        self.workflow_id = self.get_param("config.workflow_id", "")

    def run(self):
        Responder.run(self)

        parsed_url = "%s/api/v1/workflows/%s/execute" % (self.url, self.workflow_id)
        headers = {
            "Authorization": "Bearer %s"  % self.api_key
        }
        r = requests.post(parsed_url, headers=headers)
        if r.status_code == 200:
            self.report({"Message": "Executed workflow"})
        else:
            self.error(r.status_code)

if __name__ == '__main__':
    Shuffle().run()

