#!/usr/bin/env python3
# encoding: utf-8

import json
import requests
from datetime import datetime
from cortexutils.responder import Responder


class Telegram(Responder):

    def __init__(self):
        Responder.__init__(self)
        self.api_token = self.get_param(
            "config.api_token", None, "Missing Telegram bot API token")
        self.chat_id = self.get_param(
            "config.chat_id", None, "Missing Telegram Chat ID")
        self.date_format = self.get_param(
            "config.date_format", "%d.%m.%Y %H:%M")
        self.tag = self.get_param("config.tag", None)

    def run(self):
        Responder.run(self)

        # converting TheHive severities to readable
        severities = {
            1: 'Low',
            2: 'Medium',
            3: 'High',
            4: 'Critical'
        }

        caseId = self.get_param("data.caseId")
        title = self.get_param("data.title")
        severity = severities[self.get_param("data.severity", 2)]
        owner = self.get_param("data.owner")
        description = self.get_param("data.description")

        startDate_datetime = datetime.fromtimestamp(
            self.get_param("data.startDate", 0) / 1000)
        startDate_formated = startDate_datetime.strftime(self.date_format)

        # markdown syntax in TheHive is different from Telegram
        description = description.replace("**", "*")
        description = description.replace("\n\n", "\n")

        msg_content = f'#Case{caseId}\n'
        msg_content += f'*{title}*\n\n'
        msg_content += f'*Severity*: {severity}\n'
        msg_content += f'*Assignee*: {owner}\n'
        msg_content += f'*Date*: {startDate_formated}\n\n'
        msg_content += f'*Description*:\n{description}'

        msg_data = {}
        msg_data['chat_id'] = self.chat_id
        msg_data['text'] = msg_content
        msg_data['parse_mode'] = 'markdown'
        message = json.dumps(msg_data)

        hook_url = f'https://api.telegram.org/bot{self.api_token}/sendMessage'
        headers = {'content-type': 'application/json',
                   'Accept-Charset': 'UTF-8'}
        resp_code = requests.post(hook_url, headers=headers, data=message)

        self.report({"message": f"{resp_code.text}"})

    def operations(self, raw):
        if self.tag:
            return [self.build_operation("AddTagToCase", tag=self.tag)]


if __name__ == "__main__":
    Telegram().run()
