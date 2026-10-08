#!/usr/bin/env python3
from cortexutils.responder import Responder
import requests


def normalize_id_list(value):
    """Flatten a string or list custom-field value into a deduped list of ids."""
    if value is None:
        return []
    items = [value] if isinstance(value, str) else list(value)
    ids = []
    seen = set()
    for item in items:
        if not item:
            continue
        for part in str(item).split(","):
            part = part.strip()
            if part and part not in seen:
                seen.add(part)
                ids.append(part)
    return ids


class SplunkES_NotableStatusSync(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.host = self.get_param("config.host", None, "Missing Splunk host")
        self.port = self.get_param("config.port", "8089")
        self.auth_token = self.get_param("config.auth_token", None)
        self.username = self.get_param("config.username", None)
        self.password = self.get_param("config.password", None)
        self.verify_ssl = self.get_param("config.verify_ssl", True)
        self.custom_field_name_notable_event_id = self.get_param(
            "config.custom_field_name_notable_event_id", None
        )
        # Status IDs are per-instance (reviewstatuses.conf); defaults are Splunk ES factory values.
        self.status_id_new = self.get_param("config.status_id_new", "1")
        self.status_id_in_progress = self.get_param("config.status_id_in_progress", "2")
        self.status_id_closed = self.get_param("config.status_id_closed", "5")
        # Off by default: TheHive logins and Splunk usernames aren't guaranteed to match.
        self.sync_owner = self.get_param("config.sync_owner", False)

        if not self.auth_token and not (self.username and self.password):
            self.error("Provide either an auth token or a username and password")

    @property
    def base_url(self):
        return f"https://{self.host}:{self.port}"

    def stage_to_status_id(self, stage):
        return {
            "New": self.status_id_new,
            "InProgress": self.status_id_in_progress,
            "Imported": self.status_id_in_progress,
            "Closed": self.status_id_closed,
        }.get(stage)

    def get_notable_event_ids(self):
        """Read the configured custom field, falling back to sourceRef (alerts only)."""
        if self.custom_field_name_notable_event_id:
            ids = normalize_id_list(
                self.get_param(
                    f"data.customFieldValues.{self.custom_field_name_notable_event_id}", None
                )
            )
            if ids:
                return ids
        return normalize_id_list(self.get_param("data.sourceRef", None))

    def update_notable_event(self, rule_uid, status_id, comment, owner=None):
        data = {"ruleUIDs": rule_uid, "status": status_id, "comment": comment}
        if owner:
            data["newOwner"] = owner
        headers = {}
        auth = None
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        else:
            auth = (self.username, self.password)
        response = requests.post(
            f"{self.base_url}/services/notable_update",
            auth=auth,
            headers=headers,
            params={"output_mode": "json"},
            data=data,
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        result = response.json()
        if not result.get("success"):
            raise RuntimeError(result.get("message", "Unknown error"))
        return result

    def build_comment(self, current_stage):
        object_label = "case" if "thehive:case" in str(self.get_param("dataType", "")) else "alert"
        title = self.get_param("data.title", "(untitled)")
        analyst = self.get_param("parameters.user", None)
        comment = f'TheHive {object_label} "{title}" set to stage \'{current_stage}\''
        if analyst:
            comment += f" by {analyst}"
        return comment + "."

    def run(self):
        current_stage = self.get_param("data.stage", None, "Can't get case or alert stage")
        notable_event_ids = self.get_notable_event_ids()

        if not notable_event_ids:
            checked = (
                [f"custom field '{self.custom_field_name_notable_event_id}'", "sourceRef"]
                if self.custom_field_name_notable_event_id
                else ["sourceRef"]
            )
            hint = (
                " sourceRef is Alert-only in TheHive's schema; configure "
                "custom_field_name_notable_event_id if this runs on cases."
                if "thehive:case" in str(self.get_param("dataType", ""))
                else ""
            )
            self.error(
                f"No Splunk ES notable event ID found (checked: {', '.join(checked)}).{hint}"
            )
            return

        status_id = self.stage_to_status_id(current_stage)
        if status_id is None:
            self.error(f"Unknown case/alert stage: {current_stage}")
            return

        comment = self.build_comment(current_stage)
        owner = self.get_param("data.assignee", None) if self.sync_owner else None

        updated = []
        failed = []
        for rule_uid in notable_event_ids:
            try:
                self.update_notable_event(rule_uid, status_id, comment, owner)
                updated.append(rule_uid)
            except Exception as e:
                failed.append({"id": rule_uid, "error": str(e)})

        if not updated:
            self.error(
                f"Failed to update any of {len(notable_event_ids)} notable event(s) "
                f"to status '{status_id}': {failed}"
            )
            return

        message = f"Set {len(updated)}/{len(notable_event_ids)} notable event(s) to status '{status_id}'."
        if failed:
            message += f" {len(failed)} could not be updated."

        self.report({"message": message, "updated": updated, "failed": failed})


if __name__ == "__main__":
    SplunkES_NotableStatusSync().run()
