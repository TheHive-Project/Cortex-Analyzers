#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from google.oauth2 import service_account
from googleapiclient.discovery import build
import json
from thehive4py.api import TheHiveApi
from thehive4py.api import TheHiveException
from thehive4py.query import *
from urllib.parse import urlencode
from google.auth.exceptions import GoogleAuthError
from googleapiclient.errors import HttpError

class Gmail(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.service = self.get_param("config.service", None, "Service service missing")
        self.__scopes = [
            "https://mail.google.com/",
            "https://www.googleapis.com/auth/gmail.settings.basic",
        ]

        self.__gmail_service_account = {
            "type": "service_account",
            "project_id": self.get_param("config.project_id", None, "Project ID missing"),
            "private_key_id": self.get_param("config.private_key_id", None, "Private Key ID missing"),
            "private_key": self.get_param("config.private_key", None, "Private Key (PEM format) missing"),
            "client_email": self.get_param("config.client_email", None, "Client email missing"),
            "client_id": self.get_param("config.client_id", None, "Client id missing"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/{}".format(
                urlencode(self.get_param("config.client_email", None, "Client email missing"))
            )
        }

        self.__gmail_service = None
        self.__hive_service = None

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

    def __get_filter_tag(self, dataType, tags):
        """
        Get the correct tag for a dataType in a list of tags

        Returns: tag string on success else None
        """
        for tag in tags:
            if tag.find("gmail_filter:{}".format(dataType)):
                return tag
        return None

    def hive_auth(self, url, api_key):
        self.__hive_service = TheHiveApi(url, api_key)
        try:
            self.__hive_service.health()
        except TheHiveException as e:
            self.error("Responder needs TheHive connection but failed: {}".format(e))

    def gmail_impersonate(self, subject):
        """Peforms OAuth2 auth for a given service account, scope and a delegated subject

        Args:
            subject (str): email adress of the user, whos data shall be accessed (delegation)

        Returns:
            google.auth.service_account.Credentials if valid otherwise None
        """
        credentials = service_account.Credentials.from_service_account_info(
            info=self.__gmail_service_account,
            scopes=self.__scopes,
            subject=subject
        )

        if credentials.has_scopes(self.__scopes):
            return build("gmail", "v1", credentials=credentials)
        else:
            self.error("Gmail service account creation failed. Aborting responder")

    def trash_message(self, case_id, message_id):
        """Moves specified message into trash. this emails can be recovered if false-positive
        """
        # TODO:
        # this could be extended to support bulk trashing via
        # a gmail search query based on the observable dataType.
        # e.g. dataType = mail -> delete all messages where "from: <mail observable>"
        gmail_observables = self.__get_gmail_subjects(case_id, And(Eq("dataType", "mail"), EndsWith("data", "gmail.com")))
        for observable in gmail_observables:
            resource = self.gmail_impersonate(observable["data"])
            try:
                result = resource.users().messages().trash(userId=observable["data"], id=message_id).execute()
            except GoogleAuthError as e:
                self.error("Gmail oauth failed: {}".format(e))
            except HttpError as e:
                self.error("Gmail api failed: {}".format(e))
            observable["tags"].extend("gmail_trash:{}".format(result["id"]))

        for observable in gmail_observables:
            self.__hive_service.update_case_observables(observable, fields=["tags"])
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
            resource = self.gmail_impersonate(observable["data"])
            try:
                filter_id = resource.users().settings().filters().create(userId=observable["data"], body=new_filter).execute()
            except GoogleAuthError as e:
                self.error("Gmail oauth failed: {}".format(e))
            except HttpError as e:
                self.error("Gmail api failed: {}".format(e))
            observable["tags"].extend("gmail_filter:{}:{}".format(self.get_param("data.dataType"), filter_id))

        for observable in gmail_observables:
            self.__hive_service.update_case_observables(observable, fields=["tags"])
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
            tag = self.__get_filter_tag(observable["tags"]) # a tag should look like gmail_filters:domain:1235123121
            resource = self.gmail_impersonate(observable["data"])
            try:
                resource.users().settings().filters().delete(userId=observable["data"], id=tag.split(":")[-1]).execute()
            except GoogleAuthError as e:
                self.error("Gmail oauth failed: {}".format(e))
            except HttpError as e:
                self.error("Gmail api failed: {}".format(e))
            observable["tags"].remove(tag)

        for observable in gmail_observables:
            self.__hive_service.update_case_observables(observable, fields=["tags"])
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

        action = getattr(self, self.service, self.__not_found) # call respective func or fail with default
        action(observable, dataType, caseId)

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='gmail:blocked')]

if __name__ == '__main__':
    Gmail().run()