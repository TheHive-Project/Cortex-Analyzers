#!/usr/bin/env python3
# encoding: utf-8

import requests
from cortexutils.responder import Responder
from thehive4py import TheHiveApi
import datetime
import re


class Slack(Responder):

    def __init__(self):
        Responder.__init__(self)
        self.service = self.get_param("config.service")
        self.slack_token = self.get_param(
            "config.slack_token", None, "Missing Slack bot token"
        )
        if self.service == "createchannel":
            self.participants = self.get_param(
                "config.participants", [], "Missing Slack participant emails (list)"
            )
        self.channel_prefix = self.get_param(
            "config.channel_prefix", "case-", "Missing channel prefix"
        )
        self.visibility = self.get_param(
            "config.visibility", "private"
        )  # 'private' or 'public'
        self.post_summary = self.get_param("config.post_summary", True)
        self.post_description = self.get_param("config.post_description", False)
        self.thehive_base_url = self.get_param("config.thehive_base_url", None)
        self.thehive_apikey = self.get_param("config.thehive_apikey", None)

    def find_existing_channel(self, name, headers):
        url = "https://slack.com/api/conversations.list"
        cursor = None
        while True:
            params = {
                "limit": 200,
                "exclude_archived": True,
                "types": "public_channel,private_channel",
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
            channel_name = (
                f"{self.channel_prefix}{case_id}".replace(" ", "-")
                .replace(".", "")
                .replace(",", "")
                .lower()
            )
            channel_name = channel_name[:80]
            self.channel_name = channel_name

            headers = {
                "Authorization": f"Bearer {self.slack_token}",
                "Content-Type": "application/json",
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
                    print(
                        f"[WARNING] Could not resolve Slack user for email {email}: {user_data.get('error')}"
                    )
            if not user_ids:
                self.error(
                    "No valid Slack users found from participant emails. Aborting channel creation."
                )

            # 2. create channel only after we have valid users
            channel_id = self.find_existing_channel(channel_name, headers)
            if channel_id:
                # Channel already exists, reuse it
                pass
            else:
                create_url = "https://slack.com/api/conversations.create"
                payload = {
                    "name": channel_name,
                    "is_private": self.visibility == "private",
                }
                create_resp = requests.post(create_url, headers=headers, json=payload)
                create_data = create_resp.json()
                if not create_data.get("ok"):
                    self.error(
                        f"Slack channel creation failed: {create_data.get('error')}"
                    )
                channel_id = create_data["channel"]["id"]

            # 3. invite users
            if user_ids:
                invite_url = "https://slack.com/api/conversations.invite"
                invite_payload = {
                    "channel": channel_id,
                    "users": ",".join(user_ids),
                    "force": True,
                }
                invite_resp = requests.post(
                    invite_url, headers=headers, json=invite_payload
                )
                invite_data = invite_resp.json()
                if not invite_data.get("ok"):
                    self.error(f"Error inviting users: {invite_data.get('error')}")

            # 4. post a summary message
            if self.post_summary:
                post_url = "https://slack.com/api/chat.postMessage"

                def format_severity(score):
                    return {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}.get(
                        score, "UNKNOWN"
                    )

                def format_tlp(level):
                    return {
                        -1: "UNKNOWN",
                        0: "WHITE",
                        1: "GREEN",
                        2: "AMBER",
                        3: "RED",
                    }.get(level, "UNKNOWN")

                severity = format_severity(self.get_param("data.severity", 2))
                tlp = format_tlp(self.get_param("data.tlp", 2))
                status = self.get_param("data.extendedStatus", "New")

                case_link_text = ""
                if self.thehive_base_url:
                    case_web_link = (
                        f"{self.thehive_base_url}/cases/{case_unique_id}/details"
                    )
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

                post_payload = {"channel": channel_id, "text": summary}
                post_resp = requests.post(post_url, headers=headers, json=post_payload)
                post_data = post_resp.json()
                if not post_data.get("ok"):
                    self.error(
                        f"[ERROR] Failed to post summary message: {post_data.get('error')}"
                    )

            self.report(
                {
                    "channel_name": channel_name,
                    "channel_id": channel_id,
                    "invited_users": user_ids,
                    "message": f"Slack channel `{channel_name}` created and users invited.",
                }
            )

        elif self.service == "syncchannel":
            case_id = self.get_param("data.caseId")
            case_unique_id = self.get_param("data.id")

            # Collect all channel names from tags
            channel_names = []
            case_tags = self.get_param("data.tags", [])
            for tag in case_tags:
                if tag.startswith("slack:"):
                    channel_names.append(tag[6:])  # Remove "slack:" prefix

            # Fallback to reconstructing channel name if no tags found
            if not channel_names:
                channel_name = (
                    f"{self.channel_prefix}{case_id}".replace(" ", "-")
                    .replace(".", "")
                    .replace(",", "")
                    .lower()
                )
                channel_name = channel_name[:80]
                channel_names.append(channel_name)

            headers = {
                "Authorization": f"Bearer {self.slack_token}",
                "Content-Type": "application/json",
            }

            # Sync all channels
            synced_channels = []
            errors = []

            for channel_name in channel_names:
                try:
                    # Find the channel
                    channel_id = self.find_existing_channel(channel_name, headers)
                    if not channel_id:
                        errors.append(f"Channel '{channel_name}' not found")
                        continue

                    # Get channel conversation history
                    conversation_data = self.get_channel_conversations(channel_id, headers)

                    # Create or update TheHive task with conversation data
                    task_id, action = self.create_or_update_thehive_task(
                        case_unique_id, channel_name, conversation_data
                    )

                    synced_channels.append({
                        "channel_name": channel_name,
                        "channel_id": channel_id,
                        "task_id": task_id,
                        "action": action
                    })

                except Exception as e:
                    errors.append(f"Error syncing '{channel_name}': {str(e)}")

            # Build report
            if not synced_channels and errors:
                self.error(f"Failed to sync channels: {', '.join(errors)}")

            report_data = {
                "synced_channels": synced_channels,
                "total_synced": len(synced_channels),
                "message": f"Synced {len(synced_channels)} channel(s)"
            }

            if errors:
                report_data["errors"] = errors

            self.report(report_data)

    def get_channel_conversations(self, channel_id, headers):
        """Retrieve all conversations from a Slack channel"""
        url = "https://slack.com/api/conversations.history"
        conversations = []
        cursor = None

        while True:
            params = {"channel": channel_id, "limit": 200}
            if cursor:
                params["cursor"] = cursor

            response = requests.get(url, headers=headers, params=params)
            data = response.json()

            if not data.get("ok"):
                self.error(f"Failed to retrieve channel history: {data.get('error')}")

            messages = data.get("messages", [])
            conversations.extend(messages)

            cursor = data.get("response_metadata", {}).get("next_cursor")
            if not cursor:
                break

        # Sort messages chronologically
        conversations.sort(key=lambda x: float(x.get("ts", 0)))

        return conversations

    def download_file_attachment(self, file_info, headers):
        """Download file attachments from Slack"""
        try:
            file_url = (file_info.get("url_private_download") or
                       file_info.get("url_private") or
                       file_info.get("url_download"))
            if not file_url:
                return None

            response = requests.get(file_url, headers=headers, allow_redirects=True)

            if response.status_code == 200 and len(response.content) > 0:
                # Verify we got actual file content, not HTML
                if not response.content.startswith((b"<!DOCTYPE html", b"<html")):
                    return {
                        "name": file_info.get("name", "unknown"),
                        "content": response.content,
                        "mimetype": file_info.get(
                            "mimetype", "application/octet-stream"
                        ),
                    }

        except requests.RequestException:
            return None

        return None

    def find_existing_task(self, api, case_id, task_title):
        """Find existing task by title in the case"""
        try:
            # Use the correct thehive4py v2 method: case.find_tasks()
            case_tasks = api.case.find_tasks(case_id)
            
            if case_tasks:
                for task in case_tasks:
                    title = task.get("title") if isinstance(task, dict) else getattr(task, "title", None)
                    if title == task_title:
                        return task
            
            return None

        except Exception:
            return None

    def get_slack_username(self, user_id, headers):
        """Convert Slack user ID to readable username"""
        if not user_id or user_id == "unknown":
            return "Unknown User"

        try:
            # Check cache first to avoid repeated API calls
            if not hasattr(self, "_user_cache"):
                self._user_cache = {}

            if user_id in self._user_cache:
                return self._user_cache[user_id]

            # Get user info from Slack API
            url = "https://slack.com/api/users.info"
            params = {"user": user_id}
            response = requests.get(url, headers=headers, params=params)
            data = response.json()

            if data.get("ok") and data.get("user"):
                user = data["user"]
                profile = user.get("profile", {})
                username = (profile.get("display_name") or
                           profile.get("real_name") or
                           user.get("name", user_id))

                self._user_cache[user_id] = username
                return username

            self._user_cache[user_id] = user_id
            return user_id

        except Exception:
            return user_id

    def format_slack_message_text(self, text, headers):
        """Clean up Slack message text for better markdown display"""
        if not text:
            return "_No text content_"

        # Convert Slack user mentions from <@U123456> to @username format
        def replace_user_mention(match):
            user_id = match.group(1)
            username = self.get_slack_username(user_id, headers)
            return f"@**{username}**"

        text = re.sub(r"<@([A-Z0-9]+)>", replace_user_mention, text)

        # Convert channel mentions
        text = re.sub(r"<#([A-Z0-9]+)\|([^>]+)>", r"#**\2**", text)
        text = re.sub(r"<#([A-Z0-9]+)>", r"#\1", text)

        # Convert links to proper markdown
        text = re.sub(r"<(https?://[^|>]+)\|([^>]+)>", r"[\2](\1)", text)
        text = re.sub(r"<(https?://[^>]+)>", r"\1", text)

        # Handle Slack formatting to markdown
        text = re.sub(r"\*([^*]+)\*", r"**\1**", text)  # Bold
        text = re.sub(r"_([^_]+)_", r"*\1*", text)  # Italic
        text = re.sub(r"`([^`]+)`", r"`\1`", text)  # Code (already correct)
        text = re.sub(
            r"```([^`]+)```", r"```\1```", text
        )  # Code blocks (already correct)

        # Handle special Slack formatting
        text = text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")

        # Convert line breaks to proper markdown
        text = text.replace("\n", "\n")

        return text

    def get_existing_slack_messages(self, api, task_id):
        """Get existing Slack message IDs from task logs to avoid duplicates"""
        try:
            logs = api.task.find_logs(task_id)
            if logs:
                existing_message_ids = set()
                for log in logs:
                    message_text = log.get("message", "")
                    timestamp_match = re.search(
                        r"Slack timestamp: (\d+\.\d+)", message_text
                    )
                    if timestamp_match:
                        existing_message_ids.add(timestamp_match.group(1))
                return existing_message_ids
            return set()
        except Exception:
            return set()

    def create_task_log(self, api, task_id, message, timestamp=None, attachments=None):
        """Create a task log entry with optional attachments"""
        try:
            log_data = {"message": message}
            if timestamp:
                log_data["date"] = int(float(timestamp) * 1000)

            log_response = api.task.create_log(task_id, log_data)

            log_id = getattr(log_response, '_id', None) or (log_response.get('_id') if hasattr(log_response, 'get') else None)

            # Add attachments if available
            uploaded_attachments = []
            if attachments and log_id:
                uploaded_attachments = self.add_attachments_to_log(api, task_id, log_id, attachments)

            return True, log_id, uploaded_attachments
        except Exception:
            return False, None, []

    def add_attachments_to_log(self, api, task_id, log_id, attachments):
        """Add file attachments to a task log and return attachment info"""
        import tempfile
        import os

        try:
            temp_files = []
            attachment_info = []

            for attachment in attachments:
                if attachment and "content" in attachment:
                    # Preserve original filename
                    import tempfile
                    temp_dir = tempfile.gettempdir()
                    original_name = attachment.get('name', 'attachment')
                    temp_path = os.path.join(temp_dir, f"slack_attachment_{original_name}")
                    
                    # Handle duplicate names
                    counter = 1
                    while os.path.exists(temp_path):
                        name_parts = original_name.rsplit('.', 1)
                        if len(name_parts) == 2:
                            temp_path = os.path.join(temp_dir, f"slack_attachment_{name_parts[0]}_{counter}.{name_parts[1]}")
                        else:
                            temp_path = os.path.join(temp_dir, f"slack_attachment_{original_name}_{counter}")
                        counter += 1
                    
                    with open(temp_path, 'wb') as temp_file:
                        temp_file.write(attachment["content"])
                        temp_files.append(temp_path)
                        attachment_info.append(attachment)

            if temp_files:
                response = api.task_log.add_attachment(log_id, temp_files)
                
                # Get attachment IDs
                attachment_ids = []
                try:
                    logs = api.task.find_logs(task_id)
                    for log in logs:
                        if log.get('_id') == log_id and log.get('attachments'):
                            attachment_ids.extend([att['_id'] for att in log['attachments'] if att.get('_id')])
                            break
                except:
                    try:
                        log_detail = api.task_log.get(log_id)
                        attachments = getattr(log_detail, 'attachments', log_detail.get('attachments', []))
                        attachment_ids = [att['_id'] for att in attachments if att.get('_id')]
                    except:
                        pass
                
                # Clean up temporary files
                for temp_file in temp_files:
                    try:
                        os.unlink(temp_file)
                    except:
                        pass
                
                # Return attachment info with IDs
                result = []
                for i, info in enumerate(attachment_info):
                    attachment_data = info.copy()
                    if i < len(attachment_ids):
                        attachment_data['attachment_id'] = attachment_ids[i]
                    result.append(attachment_data)
                return result

        except Exception:
            pass
        return []

    def update_log_with_attachment_previews(self, api, task_id, log_id, original_message, uploaded_attachments):
        """Update task log message to include markdown previews of uploaded attachments"""
        try:
            preview_lines = []
            for attachment in uploaded_attachments:
                if 'attachment_id' in attachment:
                    file_name = attachment.get('name', 'unknown')
                    attachment_id = attachment['attachment_id']
                    preview_line = f"![{file_name}](/api/v1/attachment/{attachment_id})"
                    preview_lines.append(preview_line)
            
            if preview_lines:
                # Insert previews right before the metadata section
                metadata_marker = "\n\n---\n_Slack message from"
                if metadata_marker in original_message:
                    parts = original_message.split(metadata_marker)
                    updated_message = parts[0] + "\n\n" + "\n".join(preview_lines) + metadata_marker + parts[1]
                else:
                    updated_message = original_message + "\n\n" + "\n".join(preview_lines)
                
                # Update the task log with the new message including previews
                update_data = {"message": updated_message}
                api.task_log.update(log_id, update_data)
                
        except Exception:
            pass

    def sync_conversations_as_logs(self, api, task_id, conversations, channel_name):
        """Sync Slack conversations as individual task logs"""
        headers = {
            "Authorization": f"Bearer {self.slack_token}",
            "Content-Type": "application/json",
        }

        existing_message_ids = self.get_existing_slack_messages(api, task_id)

        new_logs_count = 0
        attachments_count = 0
        skipped_count = 0

        for msg in conversations:
            message_ts = msg.get("ts", "0")

            # Skip if already synced
            if message_ts in existing_message_ids:
                skipped_count += 1
                continue

            timestamp_float = float(message_ts)
            dt = datetime.datetime.utcfromtimestamp(timestamp_float)
            formatted_time = dt.strftime("%H:%M:%S")
            formatted_time_with_tz = f"{formatted_time} (UTC)"
            formatted_date = dt.strftime("%Y-%m-%d")

            user_id = msg.get("user", "unknown")
            raw_text = msg.get("text", "")

            # Get readable username
            username = self.get_slack_username(user_id, headers)

            # Format message text for markdown
            formatted_text = self.format_slack_message_text(raw_text, headers)

            # Handle special message types
            subtype = msg.get("subtype")
            if subtype == "channel_join":
                formatted_text = f"_👋 **{username}** joined the channel_"
            elif subtype == "channel_leave":
                formatted_text = f"_👋 **{username}** left the channel_"
            elif subtype == "channel_topic":
                formatted_text = (
                    f"_📌 **{username}** set the channel topic: {formatted_text}_"
                )

            # Handle file attachments with better formatting
            files = msg.get("files", [])
            message_attachments = []
            attachment_text = ""
            
            if files:
                image_count = 0
                file_count = 0
                for file_info in files:
                    file_type = file_info.get("filetype", "unknown")
                    mimetype = file_info.get("mimetype", "")

                    # Check if it's an image
                    is_image = (mimetype and mimetype.startswith("image/")) or file_type.lower() in ["png", "jpg", "jpeg", "gif", "webp", "svg"]
                    
                    if is_image:
                        image_count += 1
                    else:
                        file_count += 1
                    
                    attachments_count += 1

                    # Download attachment for actual file upload
                    file_data = self.download_file_attachment(file_info, headers)
                    if file_data:
                        message_attachments.append(file_data)
                
                # Create attachment summary text
                attachment_parts = []
                if image_count > 0:
                    if image_count == 1:
                        attachment_parts.append("[Image #1]")
                    else:
                        attachment_parts.append(f"[Images #1-#{image_count}]")
                
                if file_count > 0:
                    if file_count == 1:
                        attachment_parts.append("[File #1]")
                    else:
                        attachment_parts.append(f"[Files #1-#{file_count}]")
                
                if attachment_parts:
                    attachment_text = " " + " ".join(attachment_parts)

            # Update log message format with attachments
            content_part = formatted_text if formatted_text.strip() else ""
            if content_part and attachment_text:
                log_message = f"***{username}** at `{formatted_time_with_tz}`*:\n\n---\n\n{content_part}{attachment_text}"
            elif content_part:
                log_message = f"***{username}** at `{formatted_time_with_tz}`*:\n\n---\n\n{content_part}"
            elif attachment_text:
                log_message = f"***{username}** at `{formatted_time_with_tz}`*:{attachment_text}"
            else:
                log_message = f"***{username}** at `{formatted_time_with_tz}`*"

            # Add metadata at the bottom for technical reference (for display)
            log_message += (
                f"\n\n---\n_Slack message from {formatted_date} | ID: {message_ts}_"
            )

            # Add metadata for deduplication
            log_message += f"\nSlack timestamp: {message_ts}"

            # Create the task log with attachments
            success, log_id, uploaded_attachments = self.create_task_log(
                api, task_id, log_message, message_ts, message_attachments
            )
            if success:
                new_logs_count += 1
                
                # If attachments were uploaded, update the log message with previews
                if uploaded_attachments:
                    self.update_log_with_attachment_previews(api, task_id, log_id, log_message, uploaded_attachments)
        return new_logs_count, attachments_count

    def create_or_update_thehive_task(self, case_id, channel_name, conversations):
        """Create or update a TheHive task with the channel conversation"""
        if not self.thehive_base_url or not self.thehive_apikey:
            self.error(
                "TheHive API configuration missing (thehive_base_url or thehive_apikey)"
            )

        # Initialize TheHive API
        api = TheHiveApi(self.thehive_base_url, self.thehive_apikey)

        # Prepare minimal task description
        task_description = f"Slack Channel Sync for {channel_name}\n\nThis task contains conversation history from Slack channel {channel_name} as individual task logs."

        task_title = f"Slack Channel Sync: {channel_name}"

        # Check if task already exists
        existing_task = self.find_existing_task(api, case_id, task_title)

        if existing_task:
            task_id = existing_task.get('_id') if isinstance(existing_task, dict) else existing_task._id

            try:
                # Sync conversations as individual task logs
                new_logs_count, attachments_count = self.sync_conversations_as_logs(
                    api, task_id, conversations, channel_name
                )

                return (
                    task_id,
                    f"updated ({new_logs_count} new messages, {attachments_count} attachments)",
                )

            except Exception as e:
                self.error(f"Failed to update task: {str(e)}")
        else:
            # Task doesn't exist, create new one
            task_data = {
                "title": task_title,
                "description": task_description,
                "group": "Communication",
                "order": 0,
            }

            try:
                # Use the task endpoint to create a task
                response = api.task.create(case_id, task_data)


                task_id = getattr(response, '_id', None) or (response.get('_id') if hasattr(response, 'get') else None)

                if task_id:
                    # Sync conversations as individual task logs
                    new_logs_count, attachments_count = self.sync_conversations_as_logs(
                        api, task_id, conversations, channel_name
                    )

                    return (
                        task_id,
                        f"created ({new_logs_count} messages, {attachments_count} attachments)",
                    )
                else:
                    self.error(f"Failed to extract task ID from response: {response}")

            except Exception as e:
                self.error(f"Failed to create task: {str(e)}")
                
    def operations(self, raw):
        artifacts = []
        # AddTagToArtifact ({ "type": "AddTagToArtifact", "tag": "tag to add" }): add a tag to the artifact related to the object
        # AddTagToCase ({ "type": "AddTagToCase", "tag": "tag to add" }): add a tag to the case related to the object
        # MarkAlertAsRead: mark the alert related to the object as read
        # AddCustomFields ({"name": "key", "value": "value", "tpe": "type"): add a custom field to the case related to the object
        if self.service == "createchannel":
            if hasattr(self, 'channel_name'):
                artifacts.append(self.build_operation("AddTagToCase", tag=f"slack:{self.channel_name}"))
        return artifacts


if __name__ == "__main__":
    Slack().run()
