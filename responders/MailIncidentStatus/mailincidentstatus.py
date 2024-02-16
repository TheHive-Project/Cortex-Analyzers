#!/usr/bin/env python3
# encoding: utf-8

import ssl
import smtplib
import datetime
from cortexutils.responder import Responder
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
from thehive4py.api import TheHiveApi


class MailIncidentStatus(Responder):
    def __init__(self):
        Responder.__init__(self)
        # Mail settings
        self.smtp_host = self.get_param("config.smtp_host", "localhost")
        self.smtp_port = self.get_param("config.smtp_port", "25")
        self.mail_from = self.get_param(
            "config.from", None, "Missing sender email address"
        )
        self.smtp_user = self.get_param("config.smtp_user", "user", None)
        self.smtp_pwd = self.get_param("config.smtp_pwd", "pwd", None)
        # TheHive4py settings
        self.thehive_url = self.get_param(
            "config.thehive_url", None, "TheHive URL missing!"
        )
        self.thehive_apikey = self.get_param(
            "config.thehive_apikey", None, "TheHive API key missing!"
        )
        self.tlp_green_mail_domains = self.get_param(
            "config.tlp_green_mail_domains",
            None,
            "Error reading tlp_green_mail_domains",
        )
        self.tlp_amber_mail_addresses = self.get_param(
            "config.tlp_amber_mail_addresses",
            None,
            "Error reading tlp_amber_mail_addresses",
        )

    def run(self):
        Responder.run(self)

        # Validate Config
        self.validate_Config()

        # Check data_type
        if not self.data_type == "thehive:case":
            self.error("data type not type 'thehive:case'")

        caseID = self.get_param("data.id", None, "case.id is missing")

        # CREATE MAIL BODY
        body = self.get_HTMLMailBody()

        # GET RECIPIENTS
        # Search recipient address in case tags
        tags = self.get_param("data.tags", None, "recipient address not found in tags")
        mail_addresses = [
            t[5:].strip('"')
            for t in tags
            if t.startswith("mail=") or t.startswith("mail:")
        ]
        if len(mail_addresses) == 0:
            self.error("recipient address not found in tags")

        # CHECK RECIPIENTS FOR CONFORMANCE WITH TLP
        self.check_TLPConformance(mail_addresses)

        # PREPARE MAIL

        # SEND MAIL
        message = ""
        for mail_address in mail_addresses:
            msg = MIMEMultipart()
            subject = (
                self.get_param("config.mail_subject_prefix", "", None)
                + caseID
                + " "
                + self.get_param("data.title", None, "title is missing")
            )
            msg["Subject"] = subject
            msg["From"] = self.mail_from
            msg["Date"] = formatdate(localtime=True)

            # msg.attach(MIMEText(body, "plain", "utf-8"))
            msg.attach(MIMEText(body, "html", "utf-8"))
            msg["To"] = mail_address

            if self.smtp_user and self.smtp_pwd:
                try:
                    context = ssl.create_default_context()
                    with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                        server.ehlo()
                        server.starttls(context=context)
                        server.ehlo()
                        server.login(self.smtp_user, self.smtp_pwd)
                        server.send_message(msg, self.mail_from, mail_address)
                except smtplib.SMTPNotSupportedError:
                    with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                        server.ehlo()
                        server.login(self.smtp_user, self.smtp_pwd)
                        server.send_message(msg, self.mail_from, mail_address)
            else:
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    server.send_message(msg, self.mail_from, mail_address)

            # SET RETURN MESSAGE
            message += "message sent to " + mail_address + ";"
        self.report({"message": message})

    def validate_Config(self):
        """
        The configuration contains mail domains and mail addresses. This is validated before.
        """
        status = True
        # Check mail domains
        for domain in self.tlp_green_mail_domains:
            # Just a simple basic step if a '.' is part of the string
            if "." not in domain:
                self.error(
                    domain
                    + " is no valid domain name. Please change configuration 'tlp_green_mail_domains'"
                )
                status = False
        # Check mail addresses
        for address in self.tlp_amber_mail_addresses:
            # Just a simple basic step if an @ is part of the string
            if "@" not in address:
                self.error(
                    address
                    + " is no valid mail address. Please change configuration 'tlp_amber_mail_addresses'"
                )
                status = False
        return status

    def check_TLPConformance(self, mail_addresses):
        """
        The TLP should be respected when sending the incident status. The following rules are applied:
        * TLP: Red  :   Sending mails not allowd -> Error is returned
        * TLP: Amber:   Check if mail address is listed in configuration item 'tlp_amber_mail_domains'
        * TLP: Green:   Check if mail domain is listed in configuration item 'tlp_green_mail_domains'
        * TLP: White:   No checks applied, every recipient receives an email
        """
        tlp = self.get_param("data.tlp", None, "Reading data.tlp failed.")
        if tlp == 0:
            # tlp:white
            pass
        elif tlp == 1:
            # tlp:green
            domains = list(map(lambda x: x.split("@")[1], mail_addresses))
            for domain in domains:
                if domain not in self.tlp_green_mail_domains:
                    self.error(
                        "No mails sent. The domain '"
                        + domain
                        + "'is not listed in the configuration. Add the domain to the configuration or remove the mail addresses with this domains from the incident case tags.\n\nCurrent tlp_green_mail_domains config:\n"
                        + ",".join(self.tlp_green_mail_domains)
                    )
        elif tlp == 2:
            # tlp:amber
            for mail_address in mail_addresses:
                if mail_address not in self.tlp_amber_mail_addresses:
                    self.error(
                        "No mails sent. The mail address '"
                        + mail_address
                        + "' is not listed in the configuration. Add the address to the configuration or remove the mail address from the incident case tags.\n\nCurrent tlp_amber_mail_addresses config:\n"
                        + ",".join(self.tlp_amber_mail_addresses)
                    )
        elif tlp == 3:
            self.error(
                "The incident has the TLP value 'tlp:red'. Sending mails is not allowed for this tlp classifcation."
            )
        else:
            self.error("TLP is an undefined value.")

    def get_HTMLMailBody(self):
        body = ""
        caseID = self.get_param("data.id", None, "case.id is missing")
        case_row = ("CaseID", caseID)
        title_row = ("Title", self.get_param("data.title"))
        severity_row = (
            "Severity",
            self.get_HTMLSeverityString(self.get_param("data.severity")),
        )
        tlp_row = (
            "TLP",
            str(self.get_param("data.tlp", None, "Reading data.tlp failed.")),
        )
        status_row = ("Status", self.get_param("data.status"))
        description_row = ("Description", self.get_param("data.description"))
        ## Create tasks summary
        tasks_row = ("Task Summary", self.get_HTMLCaseTaskSummary(caseID))
        ## Time and dates
        time = self.get_param(
            "data.startDate",
        )
        date_str = (datetime.datetime.fromtimestamp(time / 1e3)).strftime(
            "%m/%d/%Y %H:%M"
        )
        startDate_row = ("StartDate", date_str)
        time = self.get_param("data.createdAt")
        date_str = (datetime.datetime.fromtimestamp(time / 1e3)).strftime(
            "%m/%d/%Y %H:%M"
        )
        createdAt_row = ("createdAt", date_str)
        createdBy_row = ("createdBy", self.get_param("data.createdBy"))

        time = self.get_param("data.updatedAt")
        if time:
            date_str = (datetime.datetime.fromtimestamp(time / 1e3)).strftime(
                "%m/%d/%Y %H:%M"
            )
        else:
            date_str = "Unknown"
        updatedAt_row = ("updatedAt", date_str)

        updated_by = self.get_param("data.updatedBy")
        if updated_by:
            updatedBy_row = ("updatedBy", updated_by)
        else:
            updatedBy_row = ("updatedBy", "Unknown")

        table_rows = [
            case_row,
            title_row,
            severity_row,
            tlp_row,
            status_row,
            description_row,
            tasks_row,
            startDate_row,
            createdAt_row,
            createdBy_row,
            updatedAt_row,
            updatedBy_row,
        ]

        ## Custom fields
        cust_fields = self.get_param(
            "data.customFields", None, "Error loading customFields"
        )
        cust_field_rows = []
        for item in sorted(cust_fields):
            # value of item is dictionary with one element
            # sample: "scope-accounts-compromised":{"string":"makr"}
            cust_value_type = next(iter(cust_fields.get(item)))
            if cust_value_type == "date":
                date_int = (cust_fields.get(item)).get(cust_value_type)
                if date_int:
                    date_str = (
                        datetime.datetime.fromtimestamp(date_int / 1e3)
                    ).strftime("%m/%d/%Y %H:%M")
                else:
                    date_str = "Date not set"
                cust_value_str = date_str
            else:
                cust_value_str = str((cust_fields.get(item)).get(cust_value_type))
            cust_field_rows.append((item, cust_value_str))

        table_rows.extend(cust_field_rows)
        body = self.create_HTMLTable(table_rows)
        return body

    def get_HTMLSeverityString(self, severity):
        if severity == 1:
            return '<p style="color:DeepSkyBlue">Low</p>'
        elif severity == 2:
            return '<p style="color:Orange">Medium</p>'
        elif severity == 3:
            return '<p style="color:Red">High</p>'
        elif severity == 4:
            return '<p style="color:DarkRed">Critical</p>'
        else:
            return "Severtiy mapping failed"

    def create_HTMLTable(self, two_tuple_list):
        """
        Create a HTML tabel out of a list of string tuples. In the frist colum the first element of the tuple is representated, in the second column the second element of the tuple is present.
        """

        mail_style_tag_content = self.get_param(
            "config.mail_html_style_tag_content",
            None,
            "Error loading config 'config.mail_html_style_tag_content'",
        )

        explode_lists = "".join(
            [
                '<tr><td align="left">{}</td><td align="left">{}</td></tr>\n'.format(
                    i[0], i[1]
                )
                for i in two_tuple_list
            ]
        )

        html = (
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<head>\n"
            # meta definitions
            '<meta charset="UTF-8"/><meta http-equiv="Content-Type" content="text/html"; charset="utf-8"/>\n'
            # styles
            "<style>{}</style>\n"
            "</head>\n\n"
            "<body>\n"
            '<table width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#FFFFFF" align="center">\n'
            '<colgroup><col class="first"/><col class="second"/></colgroup>\n'
            '<tr><td colspan="2">Incident Status Report</td></tr>\n'
            "{}"
            "</table>\n"
            "</body>\n</html>\n"
        ).format(
            mail_style_tag_content,
            explode_lists,
        )

        # return the HTML code
        return html

    def get_HTMLCaseTaskSummary(self, caseID):
        """
        Get all tasks of a given incident, and calculate statistics of the task. Return them as HTML string.
        """
        # get case tasks by th4py
        api = TheHiveApi(self.thehive_url, self.thehive_apikey)
        response = api.get_case_tasks(caseID)

        # create statistics
        t_total = 0
        t_compl = 0
        t_inpro = 0
        t_waiti = 0
        t_cance = 0
        for t in response.json():
            t_total += 1
            if t["status"] == "Completed":
                t_compl += 1
            if t["status"] == "InProgress":
                t_inpro += 1
            if t["status"] == "Waiting":
                t_waiti += 1
            if t["status"] == "Cancel":
                t_cance += 1

        # in progress
        summary = (
            "Completed: {1}/{0}<br/>"
            "InProgress: {2}/{0}<br/>"
            "Waiting: {3}/{0}<br/>"
            "Canceled: {4}/{0}"
        ).format(t_total, t_compl, t_inpro, t_waiti, t_cance)
        return summary


if __name__ == "__main__":
    MailIncidentStatus().run()
