#!/usr/bin/env python3

from datetime import datetime, timedelta

from cortexutils.responder import Responder
from typing import Union

import requests


def convert_datetime_to_timestamp(dt: str) -> int:
    # Convert ISO format string to datetime object
    dt_obj = datetime.fromisoformat(dt)
    # Convert datetime object to timestamp
    timestamp = dt_obj.timestamp()
    return timestamp


def subtract_minutes_from_now(minutes) -> str:
    # Get current time (UTC) & substract datetime
    target_time = datetime.utcnow() - timedelta(minutes=minutes)
    # Format the data (ISO 8601)
    value = target_time.isoformat()
    return value


class Gatewatcher_CTI_Identity(Responder):
    def __init__(self):
        Responder.__init__(self)

        self.case_id = self.get_param("data.caseId", None, "Cannot get caseID")
        self.lis_api_key = self.get_param("config.LISApiKey", None, "Gatewatcher CTI API KEY is required")
        self.lis_base_url = "https://api.client.lastinfosec.com/v2/"
        self.theHive_api_key = self.get_param("config.theHiveApiKey", None, "theHive API KEY is required")
        self.theHive_fqdn = self.get_param("config.theHiveFQDN", None, "theHive fqdn is missing")
        self.headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) Gecko/20100101 Firefox/41.0"}
        self.domain = self.get_param("config.domain", None, "domain name is missing")
        self.data_type = self.get_param("dataType", None)
        self.datetime = self.get_param("config.minutes", None)

    def lis_get_by_domain(self, domain: str) -> list[dict[str, any]]:
        """Retrieve informations about email leaked for a domain from LIS API"""

        added_atfer = subtract_minutes_from_now(minutes=self.datetime) if self.datetime is not None else None
        response = requests.get(
            url=f"{self.lis_base_url}lis/leaked_emails/get_by_domain/{domain}",
            headers=self.headers,
            params={"api_key": self.lis_api_key, "headers": True, "added_after": added_atfer},
        )
        return self.check_response(response)

    def thehive_get_alert(self, field: str, value: str) -> list[dict[str, any]]:
        response = requests.post(
            url=f"{self.theHive_fqdn}/api/v1/query",
            headers={"Authorization": f"Bearer {self.theHive_api_key}", "Content-Type": "application/json"},
            params={"name": "get-all-alerts"},
            json={"query": [{"_name": "listAlert"}, {"_name": "filter", "_and": [{"_field": field, "_value": value}]}]},
        )
        if response.status_code != 200:
            self.error(f"Bad status: {response.status_code}. {response.text}")
        return response.json()

    def thehive_update_alert(self, alert_id: str, payload: dict[str, any]) -> None:
        response = requests.patch(
            url=f"{self.theHive_fqdn}/api/v1/alert/{alert_id}",
            headers={"Authorization": f"Bearer {self.theHive_api_key}", "Content-Type": "application/json"},
            json=payload,
        )
        if response.status_code != 204:
            self.error(f"Bad status: {response.status_code}. {response.text}")

    def thehive_generate_alert(self, data) -> Union[str, None]:
        email = data.get("Value")
        # Check if there is already an alert for the email
        alerts = self.thehive_get_alert(field="sourceRef", value=f"Gatewatcher CTI Identity - {email}")
        if len(alerts) > 0:
            alert = alerts[0]
            alert_id = alert.get("_id")
            # Update the alert if the email leaked again
            if alert.get("_updatedAt") is not None:
                if alert.get("_updatedAt") < convert_datetime_to_timestamp(data.get("ModificationDate")):
                    payload = {"description": str(data)}
                    if alert.get("stage") == "Closed":
                        payload["status"] = "New"
                    self.thehive_update_alert(alert_id=alert_id, payload=payload)
                    return alert_id
        else:
            tags = ["leaked"]
            if data.get("leaked_type") is not None:
                tags.append(data.get("leaked_type"))
            email = data.get("Value")
            alert_data = {
                "type": "email leaked",
                "source": "Gatewatcher CTI Identity",
                "sourceRef": f"Gatewatcher CTI Identity - {email}",
                "title": f"'{email}' is leaked",
                "tags": tags,
                "description": str(data),
                "observables": [{"dataType": "mail", "data": email, "tags": tags}],
            }
            response = requests.post(
                url=f"{self.theHive_fqdn}/api/v1/alert",
                headers={"Authorization": f"Bearer {self.theHive_api_key}", "Content-Type": "application/json"},
                json=alert_data,
            )
            if response.status_code != 201:
                self.error(f"Bad status: {response.status_code}. {response.text}")
            alert = response.json()
            return alert.get("_id")

    def thehive_unlink_alert(self, case_id: str, alert_id: str) -> None:
        response = requests.delete(
            url=f"{self.theHive_fqdn}/api/v1/case/{case_id}/alert/{alert_id}",
            headers={"Authorization": f"Bearer {self.theHive_api_key}", "Content-Type": "application/json"},
        )
        if response.status_code != 204:
            self.error(f"Bad status: {response.status_code}. {response.text}")

    def thehive_import_alert_observables_to_case(self, alert_id: str, case_id: str) -> None:
        response = requests.post(
            url=f"{self.theHive_fqdn}/api/v1/alert/{alert_id}/import/{case_id}",
            headers={"Authorization": f"Bearer {self.theHive_api_key}", "Content-Type": "application/json"},
        )
        if response.status_code != 200 or response.status_code == 400:
            # If alert is already liked to a case, unlink this alert and retry
            if response.status_code == 400 and "Alert is already imported" in response.text:
                self.thehive_unlink_alert(case_id=case_id, alert_id=alert_id)
                self.thehive_import_alert_observables_to_case(alert_id=alert_id, case_id=case_id)
            else:
                self.error(f"Bad status: {response.status_code}. {response.text}")
        # Import change the status of the alert
        # Change alert status to "New"
        self.thehive_update_alert(alert_id=alert_id, payload={"status": "New"})

    def thehive_delete_case(self, case_id: str):
        response = requests.delete(
            url=f"{self.theHive_fqdn}/api/v1/case/{case_id}",
            headers={"Authorization": f"Bearer {self.theHive_api_key}", "Content-Type": "application/json"},
        )
        if response.status_code != 204:
            self.error(f"Bad status: {response.status_code}. {response.text}")

    def check_response(self, response) -> dict[str, any]:
        if response.status_code not in [200, 422]:
            try:
                result = response.json()
                if "detail" in result and "details" in result["detail"] and "error" in result["detail"]["details"][0]:
                    self.error(f'Bad status: {response.status_code}. {result["detail"]["details"][0]["error"]}')
                else:
                    self.error(f"Bad status: {response.status_code}")
            except Exception:
                self.error(f"Bad status: {response.status_code}")
        else:
            try:
                result = response.json()
                return result
            except Exception as ex:
                self.error(f"Bad Response: {ex}")

    def run(self):
        Responder.run(self)

        leaked_emails = self.lis_get_by_domain(domain=self.domain)
        observable_count = 0
        for email in leaked_emails.get("message"):
            if (alert_id := self.thehive_generate_alert(email)) is not None:
                observable_count += 1
                self.thehive_import_alert_observables_to_case(alert_id=alert_id, case_id=self.case_id)
        # If there is no leaks or leaks are already linked (with no update) to other cases, delete the case
        if observable_count == 0 or len(leaked_emails) == 0:
            self.thehive_delete_case(case_id=self.case_id)
        self.report({"result": "Leaked emails by domain check is a success"})


if __name__ == "__main__":
    Gatewatcher_CTI_Identity().run()
