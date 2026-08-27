#!/usr/bin/env python3
from cortexutils.responder import Responder
import requests

# Fallback when reason_map config is empty; also mirrored into its JSON defaultValue.
DEFAULT_REASON_MAP = {
    "FalsePositive": "false_positive",
    "TruePositive": "true_positive",
    "BenignPositive": "benign_positive",
    "Duplicated": "duplicate",
    "Duplicate": "duplicate",
    "Indeterminate": "other",
    "Ignored": "other",
    "Other": "other",
}


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


def parse_pairs(entries):
    """Build a dict from 'key:value' config strings."""
    mapping = {}
    for entry in entries or []:
        if not entry or ":" not in str(entry):
            continue
        key, _, value = str(entry).partition(":")
        key, value = key.strip(), value.strip()
        if key and value:
            mapping[key] = value
    return mapping


class ElasticSecurity_AlertStatusSync(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.kibana_url = self.get_param("config.kibana_url", None, "Missing Kibana URL").rstrip("/")
        self.api_key = self.get_param("config.api_key", None)
        self.username = self.get_param("config.username", None)
        self.password = self.get_param("config.password", None)
        self.verify_ssl = self.get_param("config.verify_ssl", True)
        self.space_id = self.get_param("config.space_id", None)
        self.custom_field_name_alert_id = self.get_param("config.custom_field_name_alert_id", None)
        # Which Elastic status each TheHive stage maps to is a local policy decision.
        self.status_new = self.get_param("config.status_new", "open")
        self.status_in_progress = self.get_param("config.status_in_progress", "in-progress")
        self.status_imported = self.get_param("config.status_imported", "in-progress")
        self.status_closed = self.get_param("config.status_closed", "closed")
        self.reason_map = parse_pairs(
            self.get_param("config.reason_map", None)
        ) or dict(DEFAULT_REASON_MAP)
        self.default_close_reason = self.get_param("config.default_close_reason", "other")

        if not self.api_key and not (self.username and self.password):
            self.error("Provide either an API key or a username and password")

    @property
    def status_url(self):
        space = f"/s/{self.space_id}" if self.space_id else ""
        return f"{self.kibana_url}{space}/api/detection_engine/signals/status"

    def stage_to_status(self, stage):
        return {
            "New": self.status_new,
            "InProgress": self.status_in_progress,
            "Imported": self.status_imported,
            "Closed": self.status_closed,
        }.get(stage)

    def get_alert_ids(self):
        """Read the configured custom field, falling back to sourceRef (alerts only)."""
        if self.custom_field_name_alert_id:
            ids = normalize_id_list(
                self.get_param(f"data.customFieldValues.{self.custom_field_name_alert_id}", None)
            )
            if ids:
                return ids
        return normalize_id_list(self.get_param("data.sourceRef", None))

    def update_alerts(self, signal_ids, status, reason=None):
        headers = {"Content-Type": "application/json", "kbn-xsrf": "cortex-responder"}
        auth = None
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        else:
            auth = (self.username, self.password)

        payload = {"signal_ids": signal_ids, "status": status}
        if reason and status == "closed":
            payload["reason"] = reason

        response = requests.post(
            self.status_url, headers=headers, auth=auth, json=payload, verify=self.verify_ssl
        )
        response.raise_for_status()
        return response.json()

    def run(self):
        stage = self.get_param("data.stage", None, "Can't get case or alert stage")
        status_value = self.get_param("data.status", None)
        alert_ids = self.get_alert_ids()

        if not alert_ids:
            checked = (
                [f"custom field '{self.custom_field_name_alert_id}'", "sourceRef"]
                if self.custom_field_name_alert_id
                else ["sourceRef"]
            )
            hint = (
                " sourceRef is Alert-only in TheHive's schema; configure "
                "custom_field_name_alert_id if this runs on cases."
                if "thehive:case" in str(self.get_param("dataType", ""))
                else ""
            )
            self.error(f"No Elastic alert ID found (checked: {', '.join(checked)}).{hint}")
            return

        status = self.stage_to_status(stage)
        if status is None:
            self.error(f"Unknown case/alert stage: {stage}")
            return

        reason = None
        if status == "closed":
            reason = self.reason_map.get(status_value, self.default_close_reason)

        try:
            result = self.update_alerts(alert_ids, status, reason)
        except Exception as e:
            self.error(f"Failed to update {len(alert_ids)} Elastic alert(s) to '{status}': {e}")
            return

        # Bulk call: partial success is in the response body, not an exception.
        updated = result.get("updated", 0)
        failures = result.get("failures", [])
        conflicts = result.get("version_conflicts", 0)

        if not updated:
            self.error(
                f"No Elastic alert was updated to '{status}'. Checked {len(alert_ids)} ID(s); "
                f"they may not exist in this space. failures={failures} conflicts={conflicts}"
            )
            return

        message = f"Set {updated}/{len(alert_ids)} Elastic alert(s) to '{status}'"
        if reason:
            message += f" with reason '{reason}'"
        message += "."
        if updated < len(alert_ids):
            message += f" {len(alert_ids) - updated} ID(s) matched nothing."
        if failures:
            message += f" {len(failures)} failed."
        if conflicts:
            message += f" {conflicts} version conflict(s)."

        self.report({
            "message": message,
            "status": status,
            "reason": reason,
            "requested": alert_ids,
            "updated": updated,
            "failures": failures,
            "version_conflicts": conflicts,
        })


if __name__ == "__main__":
    ElasticSecurity_AlertStatusSync().run()
