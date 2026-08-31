#!/usr/bin/env python3
# encoding: utf-8

import email
import time
import uuid

import requests
from cortexutils.responder import Responder


REGION_URLS = {
    "us": "https://cloudinfra-gw-us.portal.checkpoint.com",
    "eu": "https://cloudinfra-gw.portal.checkpoint.com",
    "ca": "https://cloudinfra-gw.ca.portal.checkpoint.com",
    "au": "https://cloudinfra-gw.ap.portal.checkpoint.com",
    "uk": "https://cloudinfra-gw.uk.portal.checkpoint.com",
    "uae": "https://cloudinfra-gw.me.portal.checkpoint.com",
    "in": "https://cloudinfra-gw.in.portal.checkpoint.com",
    "sg": "https://cloudinfra-gw.sg.portal.checkpoint.com",
}

REQUEST_TIMEOUT = 30
TASK_POLL_INTERVAL = 3
TASK_POLL_MAX_ATTEMPTS = 20
DEFAULT_SEARCH_START_DATE = "2020-01-01T00:00:00Z"


class CheckPointHECResponder(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.service = self.get_param(
            "config.service", None, "Service parameter is missing"
        )
        self.client_id = self.get_param(
            "config.client_id", None, "Client ID is missing"
        )
        self.client_secret = self.get_param(
            "config.client_secret", None, "Client Secret is missing"
        )
        region = self.get_param("config.region", "eu").lower()
        if region not in REGION_URLS:
            self.error(
                "Invalid region '{}'. Must be one of: {}".format(
                    region, ", ".join(REGION_URLS.keys())
                )
            )
        self.base_url = REGION_URLS[region]
        self.saas = self.get_param("config.saas", "office365_emails")
        self.token = None
        self.token_expiry = 0

    def _authenticate(self):
        if self.token and time.time() < self.token_expiry:
            return
        url = "{}/v2/auth/external".format(self.base_url)
        resp = requests.post(
            url,
            json={"accessKey": self.client_secret},
            headers={"cloudinfra-external-client-id": self.client_id},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            self.error(
                "Authentication failed (HTTP {}): {}".format(
                    resp.status_code, resp.text
                )
            )
        body = resp.json()
        data = body.get("data", body)
        self.token = data.get("token")
        if not self.token:
            self.error("Authentication failed: no token in response")
        self.token_expiry = time.time() + float(data.get("expiresIn", 3600)) - 60

    def _headers(self):
        return {
            "Authorization": "Bearer {}".format(self.token),
            "x-av-req-id": str(uuid.uuid4()),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _api_url(self, path):
        return "{}/app/hec-api/v1.0/{}".format(self.base_url, path)

    def _check_envelope(self, body, context):
        """HEC returns HTTP 200 with a non-200 responseEnvelope.responseCode on logical failures."""
        envelope = body.get("responseEnvelope", {}) if isinstance(body, dict) else {}
        code = envelope.get("responseCode")
        if code is not None and code != 200:
            detail = envelope.get("responseText") or envelope.get("additionalText") or ""
            self.error("{} failed (responseCode {}): {}".format(context, code, detail))

    def _find_inner_message(self, msg):
        """Walk MIME parts to find an attached original email (message/rfc822)."""
        for part in msg.walk():
            if part.get_content_type() == "message/rfc822":
                payload = part.get_payload()
                if isinstance(payload, list) and len(payload) > 0:
                    return payload[0]
                elif hasattr(payload, "get"):
                    return payload
        return None

    def _normalize_message_id(self, message_id):
        message_id = message_id.strip()
        if not message_id.startswith("<"):
            message_id = "<{}".format(message_id)
        if not message_id.endswith(">"):
            message_id = "{}>".format(message_id)
        return message_id

    def _extract_message_id(self, filepath):
        with open(filepath, "rb") as f:
            msg = email.message_from_binary_file(f)

        inner = self._find_inner_message(msg)
        if inner:
            msg = inner

        message_id = msg.get("Message-ID", "").strip()
        if not message_id:
            self.error("No Message-ID header found in the .eml file")
        return self._normalize_message_id(message_id)

    def _search_by_filter(self, extended_filters, start_date=DEFAULT_SEARCH_START_DATE):
        self._authenticate()
        payload = {
            "requestData": {
                "entityFilter": {
                    "saas": self.saas,
                    "startDate": start_date,
                },
                "entityExtendedFilter": extended_filters,
            }
        }
        resp = requests.post(
            self._api_url("search/query"),
            headers=self._headers(),
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            self.error(
                "Search failed (HTTP {}): {}".format(resp.status_code, resp.text)
            )
        body = resp.json()
        self._check_envelope(body, "Search")
        return body

    def _get_entity_ids(self, response_data):
        return [
            e.get("entityInfo", {}).get("entityId")
            for e in response_data
            if e.get("entityInfo", {}).get("entityId")
        ]

    def _search_entity_ids_by_message_id(self, message_id):
        result = self._search_by_filter([{
            "saasAttrName": "entityPayload.internetMessageId",
            "saasAttrOp": "is",
            "saasAttrValue": message_id,
        }])
        response_data = result.get("responseData", [])
        if not response_data:
            self.error(
                "Email with Message-ID '{}' not found in Check Point HEC".format(
                    message_id
                )
            )
        return self._get_entity_ids(response_data)

    def _send_action(self, entity_ids, action_name):
        self._authenticate()
        if isinstance(entity_ids, str):
            entity_ids = [entity_ids]
        payload = {
            "requestData": {
                "entityIds": entity_ids,
                "entityType": "{}_email".format(self.saas),
                "entityActionName": action_name,
            }
        }
        resp = requests.post(
            self._api_url("action/entity"),
            headers=self._headers(),
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            self.error(
                "Action '{}' failed (HTTP {}): {}".format(
                    action_name, resp.status_code, resp.text
                )
            )
        body = resp.json()
        self._check_envelope(body, "Action '{}'".format(action_name))
        return body

    def _get_task(self, task_id):
        self._authenticate()
        resp = requests.get(
            self._api_url("task/{}".format(task_id)),
            headers=self._headers(),
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        data = resp.json().get("responseData")
        if isinstance(data, list):
            data = data[0] if data else None
        return data

    def _wait_for_action_result(self, action_response):
        """Poll the async task API until completion; status is completed, failed, or queued on timeout."""
        response_data = action_response.get("responseData", [])
        task_ids = []
        for item in response_data:
            task_id = item.get("taskId")
            if task_id and task_id not in task_ids:
                task_ids.append(task_id)

        summary = {
            "status": "queued",
            "succeed": 0,
            "failed": 0,
            "total": 0,
            "action_messages": [],
            "task_ids": task_ids,
        }
        if not task_ids:
            summary["action_messages"].append(
                "No task id returned by the action API; verify the action "
                "status in the Infinity Portal"
            )
            return summary

        pending = list(task_ids)
        for _ in range(TASK_POLL_MAX_ATTEMPTS):
            still_pending = []
            for task_id in pending:
                task = self._get_task(task_id)
                if not task or task.get("status") not in ("completed", "failed"):
                    still_pending.append(task_id)
                    continue
                summary["succeed"] += task.get("succeed", 0) or 0
                summary["failed"] += task.get("failed", 0) or 0
                summary["total"] += task.get("total", 0) or 0
                if task.get("status") == "failed":
                    summary["status"] = "failed"
                for act in task.get("actions", []):
                    msg = act.get("action_message")
                    if msg:
                        summary["action_messages"].append(msg)
            pending = still_pending
            if not pending:
                if summary["status"] != "failed":
                    summary["status"] = "completed"
                return summary
            time.sleep(TASK_POLL_INTERVAL)

        summary["action_messages"].append(
            "Task(s) {} did not complete within {} seconds; verify the action "
            "status in the Infinity Portal".format(
                ", ".join(str(t) for t in pending),
                TASK_POLL_INTERVAL * TASK_POLL_MAX_ATTEMPTS,
            )
        )
        return summary

    def _run_action(self, entity_ids, action_name):
        """Send an action and wait for its result; error out if nothing succeeded."""
        action_response = self._send_action(entity_ids, action_name)
        task_summary = self._wait_for_action_result(action_response)
        if task_summary["status"] == "failed" and task_summary["succeed"] == 0:
            self.error(
                "Action '{}' failed for all {} email(s): {}".format(
                    action_name,
                    len(entity_ids),
                    "; ".join(task_summary["action_messages"]) or "no details",
                )
            )
        return task_summary

    def _result_message(self, task_summary, success_message):
        if task_summary["status"] == "queued":
            return (
                "Action queued but not yet confirmed; verify the result in "
                "the Infinity Portal"
            )
        if task_summary["failed"]:
            return "{} ({} succeeded, {} failed)".format(
                success_message, task_summary["succeed"], task_summary["failed"]
            )
        return success_message

    def run(self):
        Responder.run(self)

        data_type = self.get_param("data.dataType")

        if self.service in ("quarantine", "restore"):
            if data_type != "file":
                self.error(
                    "Unsupported data type '{}'. Only 'file' (.eml) is supported.".format(
                        data_type
                    )
                )

            filepath = self.get_param("data.attachment.filepath", None)
            if not filepath:
                self.error("No file attachment found on this observable")

            filename = self.get_param("data.attachment.name", "")
            if not filename.lower().endswith(".eml"):
                self.error("Only .eml files are supported")

            message_id = self._extract_message_id(filepath)
            entity_ids = self._search_entity_ids_by_message_id(message_id)

            if not entity_ids:
                self.error("Could not resolve entity ID for this email")

            action = "quarantine" if self.service == "quarantine" else "restore"
            task_summary = self._run_action(entity_ids, action)

            success_message = (
                "Email quarantined successfully"
                if action == "quarantine"
                else "Email restored (resent) successfully"
            )
            self.report({
                "message": self._result_message(task_summary, success_message),
                "message_id": message_id,
                "entity_ids": entity_ids,
                "action": action,
                "task_result": task_summary,
            })

        elif self.service == "quarantine_by_message_id":
            if data_type != "other":
                self.error(
                    "Unsupported data type '{}'. Only 'other' (Message-ID) is supported.".format(
                        data_type
                    )
                )

            observable_value = self.get_param("data.data", None)
            if not observable_value:
                self.error("No data found on this observable")

            message_id = self._normalize_message_id(observable_value)
            if "@" not in message_id:
                self.error(
                    "'{}' does not look like a Message-ID (expected '<...@...>')".format(
                        observable_value
                    )
                )

            entity_ids = self._search_entity_ids_by_message_id(message_id)

            if not entity_ids:
                self.error(
                    "Could not resolve entity ID for Message-ID '{}'".format(message_id)
                )

            task_summary = self._run_action(entity_ids, "quarantine")
            self.report({
                "message": self._result_message(
                    task_summary, "Email quarantined successfully"
                ),
                "message_id": message_id,
                "entity_ids": entity_ids,
                "action": "quarantine_by_message_id",
                "task_result": task_summary,
            })

        else:
            self.error("Unknown service: {}".format(self.service))

    def operations(self, raw):
        action = raw.get("action", "unknown")
        return [
            self.build_operation(
                "AddTagToArtifact",
                tag="CheckPointHEC:{}".format(action),
            )
        ]


if __name__ == "__main__":
    CheckPointHECResponder().run()
