#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import *

import json

class SendGrid(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.api_key = self.get_param('config.api_key', 'CHANGE_ME')
        self.from_email = self.get_param('config.from', None, 'Missing sender email address')

    def run(self):
        Responder.run(self)

        subject = self.get_param('data.title', None, 'title is missing')

        # format and dump the data we received into them email for content.
        # it's 2020, human operators should be able to parse JSON
        content = Content("text/plain", json.dumps(self.get_param('data', None, 'no data to work with'), indent=2))
        content = Content("text/html", '<pre>' + json.dumps(self.get_param('data', None, 'no data to work with'), indent=2) + '</pre>')

        to_emails = []

        if self.data_type == 'thehive:case':
            # pull recipient addresses from tags where prefixed with mail:
            # if multiple tags exist multiple deliveries will occur
            tags = self.get_param('data.tags', None, 'recipient address not found in tags')

            for t in tags:
              if t.startswith('mail:'):
                to_emails.append(To(t[5:]))

            if to_emails == []:
                self.error('recipient address not found in case tags')

        elif self.data_type == 'thehive:alert':
            # pull recipient address to email from artifacts?
            # NOTE: this is an artifact from the original "Mailer" responder, WTF would we email any old observable address????
            # have adjusted from Mailer behaviour, observable email address must be prefixed with "mail:" in the same way as case tags
            artifacts = self.get_param('data.artifacts', None, 'recipient address not found in observables')

            mail_artifacts = [a['data'] for a in artifacts if a.get('dataType') == 'mail' and 'data' in a]

            for t in mail_artifacts:
              if t.startswith('mail:'):
                to_emails.append(To(t[5:]))

            if to_emails == []:
                self.error('recipient address not found in alert observables')
        else:
            self.error('Invalid data type %' % self.data_type)

        if to_emails != []:
            # build the message content that we'll deliver
            message = Mail(Email(self.from_email), to_emails, subject, content)

            try:
                sg = SendGridAPIClient(self.api_key)
                response = sg.send(message)

                self.report({'message': 'message sent'})
            except Exception as e:
                self.report({'message': 'exception raised'})
        else:
            self.report({'message': 'no destination email addresses found'})

    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='mail sent')]

if __name__ == '__main__':
    SendGrid().run()

# EOF
