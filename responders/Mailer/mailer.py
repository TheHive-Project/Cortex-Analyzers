#!/usr/bin/env python3
# encoding: utf-8

import ssl
import smtplib
from cortexutils.responder import Responder
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class Mailer(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.smtp_host = self.get_param("config.smtp_host", "localhost")
        self.smtp_port = self.get_param("config.smtp_port", "25")
        self.mail_from = self.get_param(
            "config.from", None, "Missing sender email address"
        )
        self.smtp_user = self.get_param("config.smtp_user", "user", None)
        self.smtp_pwd = self.get_param("config.smtp_pwd", "pwd", None)

    def run(self):
        Responder.run(self)

        title = self.get_param("data.title", None, "title is missing")
        if self.data_type in ["thehive:case", "thehive:case_task"]:
            description = self.get_param(
                "data.description", None, "description is missing"
            )
        elif self.data_type == "thehive:alert":
            description = self.get_param(
                "data.case.description", None, "description is missing"
            )
        else:
            self.error("Invalid dataType")

        mail_to = None
        if self.data_type == "thehive:case":
            # Search recipient address in case tags
            tags = self.get_param(
                "data.tags", None, "recipient address not found in tags"
            )
            mail_tags = [
                t[5:] for t in tags if t.startswith("mail=") or t.startswith("mail:")
            ]
            if mail_tags:
                mail_to = mail_tags.pop()
            else:
                self.error("recipient address not found in tags")

        elif self.data_type == "thehive:case_task":
            # Search recipient address in tasks description
            descr_array = description.splitlines()
            if "mailto:" in descr_array[0]:
                mail_to = descr_array[0].replace("mailto:", "").strip()
            elif "mailto=" in descr_array[0]:
                mail_to = descr_array[0].replace("mailto=", "").strip()
            else:
                self.error("recipient address not found in description")
            # Set rest of description as body
            description = "\n".join(descr_array[1:])

        elif self.data_type == "thehive:alert":
            # Search recipient address in artifacts
            artifacts = self.get_param(
                "data.artifacts", None, "recipient address not found in observables"
            )
            mail_artifacts = [
                a["data"]
                for a in artifacts
                if a.get("dataType") == "mail" and "data" in a
            ]
            if mail_artifacts:
                mail_to = mail_artifacts.pop()
            else:
                self.error("recipient address not found in observables")

        msg = MIMEMultipart()
        msg["Subject"] = title
        msg["From"] = self.mail_from
        msg["To"] = mail_to
        msg.attach(MIMEText(description, "plain", "utf-8"))

        if self.smtp_user and self.smtp_pwd:
            try:
                context = ssl.create_default_context()

                # STANDARD CONNECTION, TRY ADDING TLS
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    server.login(self.smtp_user, self.smtp_pwd)
                    server.send_message(msg, self.mail_from, [mail_to])

                # SMTP_SSL CONNECTION
            except smtplib.SMTPServerDisconnected:
                with smtplib.SMTP_SSL(
                    self.smtp_host, self.smtp_port, context=context
                ) as server:
                    server.login(self.smtp_user, self.smtp_pwd)
                    server.send_message(msg, self.mail_from, [mail_to])

            except Exception:
                # STANDARD CONNECTION WITHOUT TLS
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    server.ehlo()
                    server.login(self.smtp_user, self.smtp_pwd)
                    server.send_message(msg, self.mail_from, [mail_to])
        else:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.send_message(msg, self.mail_from, [mail_to])

        self.report({"message": "message sent"})

    def operations(self, raw):
        return [self.build_operation("AddTagToCase", tag="mail sent")]


if __name__ == "__main__":
    Mailer().run()
