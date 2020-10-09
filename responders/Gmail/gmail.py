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

    def delete_message(self):
        pass

    def block_domain(self):
        pass

    def block_sender(self):
        pass

    def unblock_domain(self):
        pass

    def unblock_sender(self):
        pass

    def run(self):
        Responder.run(self)
        # check if given observable is mail or email address
        # call respective action based on flavor of the responder

    def operations(self, raw):
        pass

if __name__ == '__main__':
    Gmail().run()