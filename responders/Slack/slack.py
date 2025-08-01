#!/usr/bin/env python3
# encoding: utf-8

import json
import requests
from cortexutils.responder import Responder

class Slack(Responder):

    def __init__(self):
        Responder.__init__(self)
        self.slack_token = self.get_param(
            "config.slack_token", None, "Missing Slack bot token")
        self.participants = self.get_param(
            "config.participants", [], "Missing Slack participant emails (list)")
        self.channel_prefix = self.get_param(
            "config.channel_prefix", "case-", "Missing channel prefix")
        self.visibility = self.get_param(
            "config.visibility", "private")  # 'private' or 'public'
        self.thehive_base_url = self.get_param("config.thehive_base_url", None)
        self.post_summary = self.get_param("config.post_summary", True)
        self.post_description = self.get_param("config.post_description", False)

        self.service = self.get_param("config.service")

    def find_existing_channel(self, name, headers):
        url = "https://slack.com/api/conversations.list"
        cursor = None
        while True:
            params = {
                "limit": 200,
                "exclude_archived": True,
                "types": "public_channel,private_channel"
            }
            if cursor:
                params["cursor"] = cursor
            resp = requests.get(url, headers=headers, params=params).json()
            for ch in resp.get("channels", []):
                if ch["name"] == name:
                    return ch["id"]
            cursor = resp.get("response_metadata", {}).get("next_cursor")
            if not cursor:
                break
        return None

    def run(self):
        Responder.run(self)
        if self.service == "createchannel":
            # Gather data from TheHive case
            case_id = self.get_param("data.caseId")
            case_unique_id = self.get_param("data.id")
            title = self.get_param("data.title", "")
            owner = self.get_param("data.owner", "")
            description = self.get_param("data.description", "")

            # Slack channel name must be lowercase, <=80 chars, no spaces, no periods, no commas
            channel_name = f"{self.channel_prefix}{case_id}".replace(" ", "-").replace(".", "").replace(",", "").lower()
            channel_name = channel_name[:80]
            
            headers = {
                "Authorization": f"Bearer {self.slack_token}",
                "Content-Type": "application/json"
            }

            # 1. validate participant emails BEFORE creating the channel
            user_ids = []
            for email in self.participants:
                lookup_url = "https://slack.com/api/users.lookupByEmail"
                params = {"email": email}
                lookup_resp = requests.get(lookup_url, headers=headers, params=params)
                user_data = lookup_resp.json()
                if user_data.get("ok"):
                    user_ids.append(user_data["user"]["id"])
                else:
                    print(f"[WARNING] Could not resolve Slack user for email {email}: {user_data.get('error')}")
            if not user_ids:
                self.error("No valid Slack users found from participant emails. Aborting channel creation.")

            # 2. create channel only after we have valid users
            channel_id = self.find_existing_channel(channel_name, headers)
            if channel_id:
                print(f"Channel '{channel_name}' already exists. Reusing.")
            else:
                create_url = "https://slack.com/api/conversations.create"
                payload = {
                    "name": channel_name,
                    "is_private": self.visibility == "private"
                }
                create_resp = requests.post(create_url, headers=headers, json=payload)
                create_data = create_resp.json()
                if not create_data.get("ok"):
                    self.error(f"Slack channel creation failed: {create_data.get('error')}")
                channel_id = create_data["channel"]["id"]


            # 3. invite users
            if user_ids:
                invite_url = "https://slack.com/api/conversations.invite"
                invite_payload = {
                    "channel": channel_id,
                    "users": ",".join(user_ids),
                    "force": True

                }
                invite_resp = requests.post(invite_url, headers=headers, json=invite_payload)
                invite_data = invite_resp.json()
                if not invite_data.get("ok"):
                    self.error(f"Error inviting users: {invite_data.get('error')}")

            # 4. post a summary message
            if self.post_summary:
                post_url = "https://slack.com/api/chat.postMessage"
                
                def format_severity(score):
                    return {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}.get(score, "UNKNOWN")

                def format_tlp(level):
                    return {
                        -1: "UNKNOWN",
                        0: "WHITE",
                        1: "GREEN",
                        2: "AMBER",
                        3: "RED"
                    }.get(level, "UNKNOWN")

                severity = format_severity(self.get_param("data.severity", 2))
                tlp = format_tlp(self.get_param("data.tlp", 2))
                status = self.get_param("data.extendedStatus", "New")

                case_link_text = ""
                if self.thehive_base_url:
                    case_web_link = f"{self.thehive_base_url}/cases/{case_unique_id}/details"
                    case_link_text = f"\n🔗 <{case_web_link}|Open Case in TheHive>"   
                            
                summary_lines = [
                    "*🚨 New Slack Channel created from TheHive*",
                    f"*Case ID:* {case_id} — *{title}*",
                    f"*Owner:* {owner}",
                    f"*Severity:* {severity} | *TLP:* {tlp} | *Status:* {status}",
                ]

                if self.post_description and description.strip():
                    summary_lines.append(f"*Description:*\n{description}")

                if case_link_text:
                    summary_lines.append(case_link_text)

                summary = "\n".join(summary_lines)

                post_payload = {
                    "channel": channel_id,
                    "text": summary
                }
                post_resp = requests.post(post_url, headers=headers, json=post_payload)
                post_data = post_resp.json()
                if not post_data.get("ok"):
                    self.error(f"[ERROR] Failed to post summary message: {post_data.get('error')}")

            self.report({
                "channel_name": channel_name,
                "channel_id": channel_id,
                "invited_users": user_ids,
                "message": f"Slack channel `{channel_name}` created and users invited."
            })

if __name__ == "__main__":
    Slack().run()