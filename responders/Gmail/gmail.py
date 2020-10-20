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
        self.__hive_service = None
        self.filters = []

    def __not_found(self):
        self.error("service named {} not found.".format(self.service))

    def __get_gmail_subjects(self, caseId, query):
        """
        Get all email addresses of a case ending in @gmail.com

        Returns: Array of Observable objects on success
        """
        response =  self.__hive_service.get_case_observables(caseId, query=query)
        if response.status_code == 200:
            return response.json()
        else:
            self.error("Failed to get valid response for query: {}".format(response.status_code, response.text))

    def hive_auth(self):
        self.__hive_service = TheHiveApi(
            self.get_param("config.thehive_url"),
            self.get_param("config.thehive_api_key")
        )
        try:
            self.__hive_service.health()
        except TheHiveException as e:
            self.error("Responder needs TheHive connection but failed: {}".format(e))

    def gmail_auth(self, service_account_file, scopes, subject):
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
            self.error("Gmail service account authentication failed. Aborting responder")

    def trash_message(self, case_id, message_id):
        """Moves specified message into trash. this emails can be recovered if false-positive
        """
        # TODO:
        # this could be extended to support bulk trashing via
        # a gmail search query based on the observable dataType.
        # e.g. dataType = mail -> delete all messages where "from: <mail observable>"
        gmail_observables = self.__get_gmail_subjects(case_id, And(Eq("dataType", "mail"), EndsWith("data", "gmail.com")))
        for observable in gmail_observables:
            result = self.__gmail_service.users().messages().trash(userId=observable["data"], id=message_id).execute()
            observable["tags"].extend("gmail_trash:{}".format(result["id"]))
        # Update observables with message id
        for observable in gmail_observables:
            self.hive_api.update_case_observables(observable, fields=["tags"])
        self.report({'message': "Deleted message"})

    def block_messages(self, case_id, query):
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

        gmail_observables = self.__get_gmail_subjects(case_id, And(Eq("dataType", "mail"), EndsWith("data", "gmail.com")))
        for observable in gmail_observables:
            filter_id = self.__gmail_service.users().settings().filters().create(userId=observable["data"], body=new_filter).execute()
            observable["tags"].extend("gmail_filter:{}:{}".format(self.get_param("data.dataType"), filter_id))
        # Update observables with filter ids
        for observable in gmail_observables:
            self.hive_api.update_case_observables(observable, fields=["tags"])
        self.report({'message': "Added filters"})

    def unblock_messages(self, case_id):
        """Delete a previous created filter by filter ID
        """
        gmail_observables = self.__get_gmail_subjects(case_id, query=
            And(
                Eq("dataType", "mail"), And(
                    EndsWith("data", "gmail.com"),
                    ContainsString("tags", "gmail_filter:{}*".format(self.get_param("data.dataType")))
                )
            )
        )
        for observable in gmail_observables:
            for tag in observable["tags"]:
                if "gmail_filter:{}".format(self.get_param("data.dataType")) in tag:
                    filter_id = tag.split(":")[-1]  # a tag should look like gmail_filters:domain:1235123121
                    self.__gmail_service.users().settings().filters().delete(userId=observable["data"], id=filter_id).execute()
        self.report({'message': "Removed filters"})

    def deletemessage(self, observable, dataType, caseId):
        if dataType != "mail":
            self.error("{} needs data of type 'gmail' but {} given".format(
                self.get_param("config.service"), dataType
            ))
        self.trash_message(caseId, observable)

    def unblockdomain(self, observable, dataType, caseId):
        if dataType != "domain":
            self.error("{} needs data of type 'domain' but {} given".format(
                self.get_param("config.service"), dataType
            ))
        self.unblock_messages(caseId)

    def unblocksender(self, observable, dataType, caseId):
        if dataType != "mail":
            self.error("{} needs data of type 'mail' but {} given".format(
                self.get_param("config.service"), dataType
            ))
        self.unblock_messages(caseId)

    def blocksender(self, observable, dataType, caseId):
        if dataType != "mail":
            self.error("{} needs data of type 'mail' but {} given".format(
                self.get_param("config.service"), dataType
            ))
        self.block_messages(caseId, "from: {}".format(observable))

    def blockdomain(self, observable, dataType, caseId):
        if dataType != "domain":
            self.error("{} needs data of type 'domain' but {} given".format(
                self.get_param("config.service"), dataType
            ))
        self.block_messages(caseId, "from: {}".format(observable))

    def run(self):
        Responder.run(self)


        dataType = self.get_param("data.dataType")
        observable = self.get_param("data.data")
        caseId = self.get_param("data._parent")

        action = getattr(self, self.service, self.__not_found)
        action(observable, dataType, caseId)

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='gmail:blocked'),
                self.build_operation('AddCustomFields', name="gmailFilters", value=json.dumps(self.filters), tpe='string')]

if __name__ == '__main__':
    Gmail().run()