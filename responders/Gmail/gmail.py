#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from google.oauth2 import service_account
from googleapiclient.discovery import build
import json
from thehive4py.api import TheHiveApi
from thehive4py.api import TheHiveException
from thehive4py.query import *
from random import randint

class Gmail(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.service = self.get_param("config.service", None, "Service service missing")
        self.__scopes = [
            "https://mail.google.com/",
            "https://www.googleapis.com/auth/gmail.settings.basic",
        ]
        self.__gmail_service = None
        self.filters = []

    def __not_found(self):
        self.error("service named {} not found.".format(self.service))

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
            self.__gmail_service = build("gmail", "v1", credentials=credentials)
            return True
        else:
            return False

    def trash_message(self, subject, message_id):
        """Moves specified message into trash. this emails can be recovered if false-positive
        """
        result = self.__gmail_service.users().messages().trash(userId=subject, id=message_id).execute()

    def block_messages(self, subject, query):
        ##### STUB
        return randint(10000, 20000)
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
        #### STUB
        return
        """Delete a previous created filter by filter ID
        """
        filter_id = self.__gmail_service.users().settings().filters().delete(userId=subject, id=filter_id).execute()

    def unblockdomain(self):
        if self.hive_api._check_if_custom_field_exists("gmail_filter"):
            gmail_filters = json.loads(self.get_param("data.case.customFields.gmail_filters.string"))
            for f in gmail_filters:
                self.unblock_messages(f["subject"], f["id"])
        self.report({'message': "Removed filters"})

    def block(self):
        ### MOVE THIS INTO the respective functions e.g. blockdomain/blocksender
        data_type = self.get_param("data.dataType")
        ioc = self.get_param("data.data")
        case_id = self.get_param("data._parent")
        if data_type != "domain" and data_type != "mail":
            self.error("{} needs data of type 'domain' or 'mail' but {} given".format(
                self.get_param("config.service"), data_type
            ))
        #### MOVE THIS IN TO block_messages
        response = self.hive_api.get_case_observables(case_id, query=
            And(Eq("dataType", "mail"), EndsWith("data", "gmail.com"))
        )
        if response.status_code == 200:
            gmail_subjects = response.json()
            for s in gmail_subjects:
                f_id = self.block_messages(s["data"], "from: {}".format(ioc))
                self.filters.append({"subject": s["data"], "id": f_id})
            self.report({'message': "Added filters"})
        else:
            self.error("Failure: {}/{}".format(response.status_code, response.text))

    def blocksender(self):
        self.block()
    def blockdomain(self):
        self.block()

    def run(self):
        Responder.run(self)

        self.hive_api = TheHiveApi(self.get_param("config.thehive_url"), self.get_param("config.thehive_api_key"))
        try:
            self.hive_api.health()
        except TheHiveException as e:
            self.error("Responder needs TheHive connection but failed: {}".format(e))

        action = getattr(self, self.service, self.__not_found)
        action()


    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='gmail:blocked'),
                self.build_operation('AddCustomFields', name="gmailFilters", value=json.dumps(self.filters), tpe='string')]

if __name__ == '__main__':
    Gmail().run()