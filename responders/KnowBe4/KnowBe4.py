#!/usr/bin/python3
# encoding: utf-8

from cortexutils.responder import Responder
import requests


class KnowBe4(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.api_url = self.get_param(
            'config.api_url', None, "Base URL Missing")
        self.hive_url = self.get_param(
            'config.hive_url', None, "Hive URL Missing")
        self.api_key = self.get_param(
            'config.api_key', None, "API Key Missing")
        self.event_type = self.get_param(
            'config.event_type', None, "Event Type Missing")
        self.required_tag = self.get_param(
            'config.required_tag', None, "Required tags missing.")

    def run(self):
        Responder.run(self)

        if self.get_param('data.dataType') == 'mail':

            tags = self.get_param('data.tags')

            if self.required_tag in tags or self.required_tag is None:

                target_user = self.get_param(
                    'data.data', None, 'No email address found')

                headers = {
                    'Authorization': 'Bearer ' + self.api_key,
                    'user-agent': 'KnowBe4-Cortex-Responder',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }

                thehive_case = '{}/index.html#!/case/{}/details'.format(
                    self.hive_url, self.get_param('data.case._routing'))

                description = 'TheHive Case: {}\n Description: {}\n URL: {}'.format(self.get_param(
                    'data.case.title'), self.get_param('data.case.description'), thehive_case)

                payload = {
                    'target_user': target_user,
                    'event_type': self.event_type,
                    'description': description,
                    'risk_level': 10
                }

                r = requests.post(self.api_url,
                                  json=payload, headers=headers)

                if r.status_code == 200 | 201:
                    self.report({'message': 'Added user event.'})
                else:
                    self.error(
                        'Failed report user to KnowBe4. Status: ' + str(r.status_code))

            else:
                self.error(
                    'Email address not tagged with the required tag. ' + self.required_tag)
        else:
            self.error('Incorrect dataType. "Mail" expected.')

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='kb4:clicker')]


if __name__ == '__main__':
    KnowBe4().run()
