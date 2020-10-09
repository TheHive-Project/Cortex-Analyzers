#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from google.oauth2 import service_account
from googleapiclient.discovery import build


class Gmail(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.flavor = self.get_param("config.flavor", None, "Service flavor missing")
        self.__scopes = [
            "https://mail.google.com/",
            "https://www.googleapis.com/auth/gmail.settings.basic",
        ]

    def authenticate(self, service_account_file, scopes, subject):
        """Peforms OAuth2 auth for a given service account, scope and a delegated subject

        Args:
            service_account_file (str): Path to the service account file
            scopes (array): array of oauth2 scopes needed to operate
            subject (str): email adress of the user, whos data shall be accessed (delegation)

        Returns:
            google.auth.service_account.Credentials if valid otherwise None
        """
        credentials = service_account.Credentials.from_service_account_file(
            service_account_file,
            scopes=scopes,
            subject=subject
        )

        if (credentials.valid) and (credentials.has_scopes(scopes)):
            return credentials
        else:
            return None

    def trash_message(self, subject, message_id):
        """Moves specified message into trash. this emails can be recovered if false-positive
        """
        result = self.__gmail_service.users().messages().trash(userId=subject, id=message_id).execute()

    def block_messages(self, subject, query):
        """Automatically labels matching emails according to query argument.
        gmail search syntax can be used in query. https://support.google.com/mail/answer/7190?hl=en
        """
        new_filter = {
            "criteria": {
                "query": query
            },
            "action": { # based on https://developers.google.com/gmail/api/guides/labels
                "addLabelIds": ["TRASH"],
                "removeLabelIds": ["INBOX"]
            }
        }

        filter_id = self.__gmail_service.users().settings().filters().create(userId=subject, body=new_filter).execute()
        return filter_id

    def unblock_messages(self, subject, filter_id):
        """Delete a previous created filter by filter ID
        """
        filter_id = self.__gmail_service.users().settings().filters().delete(userId=subject, id=filter_id).execute()

    def run(self):
        Responder.run(self)
        # check if given observable is mail or email address
        # call respective action based on flavor of the responder

    def operations(self, raw):
        pass

if __name__ == '__main__':
    Gmail().run()