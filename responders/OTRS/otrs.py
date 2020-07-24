#!/usr/bin/env python3
# encoding: utf-8

from datetime import datetime
from tzlocal import get_localzone
from cortexutils.responder import Responder
from thehive4py.api import TheHiveApi
from thehive4py.models import Case
from pyotrs import Client, Ticket, Article, DynamicField

class OTRS(Responder):
    def __init__(self):
        Responder.__init__(self)

        # Config
        self.thehive_url = self.get_param("config.thehive_url", None, "TheHive URL missing!")
        self.thehive_apikey = self.get_param("config.thehive_apikey", None, "TheHive API key missing!")
        self.api = TheHiveApi(self.thehive_url,self.thehive_apikey)
        self.otrs_username = self.get_param("config.otrs_username", None, "OTRS username missing!")
        self.otrs_password = self.get_param("config.otrs_password", None, "OTRS password missing!")
        self.otrs_url = self.get_param("config.otrs_url", None, "OTRS URL missing!")
        self.otrs_queue = self.get_param("config.otrs_queue", None, "OTRS queue!")
        self.otrs_ticket_type = self.get_param("config.otrs_ticket_type", None, "OTRS ticket type missing!")
        self.otrs_communication_channel = self.get_param("config.otrs_communication_channel", None, "OTRS communication channel missing!")
        self.otrs_dynamic_fields = self.get_param("config.otrs_dynamic_fields", [])
        self.customer_table = self.get_param("config.customer_table", None, "Customer lookup table missing!")

    def run(self):
        Responder.run(self)

        # To be used only with cases
        if self.data_type != "thehive:case":
            self.error("Invalid dataType")

        # Case data
        thehive_case_id = self.get_param("data.id", None, "id is missing")

        # Create TheHive session
        try:
            thehive_session = TheHiveApi(self.thehive_url, self.thehive_apikey)
        except Exception as e:
            self.error("Failed to connect to TheHive Webservice: {}".format(e))

        # Get TheHive case
        try:
            thehive_case = thehive_session.case(thehive_case_id)
            thehive_case_url = "{}/index.html#!/case/{}/details".format(self.thehive_url, thehive_case.id)
        except Exception as e:
            self.error("Failed to get TheHive Case: {}".format(e))

        # Fail if not first responder
        if thehive_case.description.startswith("Ticket number: "):
            self.error("OTRS ticket already created")

        # Create OTRS session
        otrs_session = Client(baseurl = self.otrs_url, username = self.otrs_username, password = self.otrs_password)
        try:
            otrs_session.session_create()
        except Exception as e:
            self.error("Failed to connect to OTRS Webservice: {}".format(e))

        # Get OTRS CustomerUser from TheHive case tag
        customer_user = None
        for entry in self.customer_table:
            try:
                tag, customer = entry.split(":")
            except Exception as e:
                self.error("Failed to parse customer lookup table: {}".format(e))
            if tag in thehive_case.tags:
                customer_user = customer
                break
        if not customer_user:
            self.error("Cannot lookup OTRS CustomerUser in case tags")

        # Get OTRS DynamicFields
        parsed_otrs_dynamic_fields = []
        for entry in self.otrs_dynamic_fields:
            try:
                name, value = entry.split(":")
                parsed_otrs_dynamic_fields.append(DynamicField(name, value))
            except AttributeError as e:
                # I suspect a bug: default value shoule be an empty list.
                # I got a list with a single item NoneType. Should review
                # self.get_param method.
                pass
            except Exception as e:
                self.error("Failed to parse dynamic field: {}".format(e))
        
        # Convert priority from TheHive to OTRS style
        if thehive_case.severity >= 3:
            otrs_severity = "3 high"
        elif thehive_case.severity == 2:
            otrs_severity = "2 medium"
        else:
            otrs_severity = "1 normal"

        # Create OTRS ticket
        otrs_title = "TOBEDELETED #{} - {}".format(thehive_case.caseId, thehive_case.title)
        otrs_description = "Case number: {} ({})\nSeverity: {}\nOccurred on: {}\nTheHive Url: {}\n\n{}".format(thehive_case.caseId, thehive_case.id, otrs_severity, datetime.fromtimestamp(thehive_case.startDate/1000, tz=get_localzone()), thehive_case_url, thehive_case.description)
        otrs_ticket = Ticket.create_basic(Title = thehive_case.title, Queue = self.otrs_queue, State = "new", Priority = otrs_severity, CustomerUser = customer_user, Type = self.otrs_ticket_type)
        otrs_article = Article({
            "Subject": thehive_case.title,
            "Body": otrs_description,
            "Mime/Type": "text/html",
            "SenderType": "customer",
            "CommunicationChannel": self.otrs_communication_channel
        })
        try:
            otrs_ticket = otrs_session.ticket_create(ticket = otrs_ticket, article = otrs_article, dynamic_fields = parsed_otrs_dynamic_fields)
            otrs_ticket_id = otrs_ticket["TicketID"]
            otrs_ticket_number = otrs_ticket["TicketNumber"]
            otrs_ticket_url = "{}/otrs/index.pl?Action=AgentTicketZoom;TicketID={}".format(self.otrs_url, otrs_ticket_id)
        except Exception as e:
            self.error("Cannot create OTRS ticket: {}".format(e))

        # Update TheHive case
        thehive_case.description = "Ticket number: {}\n\rUrl: {}\n\r\n\r{}".format(otrs_ticket_number, otrs_ticket_url, thehive_case.description)
        try:
            thehive_session.update_case(thehive_case)
        except Exception as e:
            self.error("Cannot update TheHive case: {}".format(e))

        self.report({"message": "opened OTRS ticket {} ({})".format(otrs_ticket_number, otrs_ticket_id)})

if __name__ == "__main__":
    OTRS().run()

