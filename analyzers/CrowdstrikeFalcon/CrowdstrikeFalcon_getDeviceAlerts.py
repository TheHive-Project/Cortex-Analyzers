#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.analyzer import Analyzer
from falconpy import OAuth2
from falconpy import Alerts


class CrowdstrikeFalcon_getDeviceAlerts(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.client_id = self.get_param("config.client_id")
        self.client_secret = self.get_param("config.client_secret")
        self.base_url = self.get_param("config.base_url", "https://api.crowdstrike.com")
        self.alert_fields = self.get_param("config.alert_fields")
        self.days_before = self.get_param("config.days_before")

    def run(self):
        Analyzer.run(self)
        if self.data_type == 'hostname':
            try:
                auth = OAuth2(client_id=self.client_id, client_secret=self.client_secret, base_url=self.base_url)
                # Define the custom header
                extra_headers = {
                    "User-Agent": "strangebee-thehive/1.0"
                }
                alerts = Alerts(auth_object=auth, ext_headers=extra_headers)
                hostname = self.get_data()
                message = "No alerts found."
                filtered_alert_list = []
                # Search for the device ID using the hostname
                response = alerts.query_alerts(filter=f"device.hostname:'{hostname}'+product:['epp']+(created_timestamp:>='now-{self.days_before}d'+created_timestamp:<'now')")
                if 200 <= response["status_code"] < 300:
                    alert_ids = response["body"]["resources"]
                else:
                    return self.error(f"Error on getting device alert IDs : {response['body']['errors']}")

                if alert_ids:
                    # Get detailed asset information using the device ID

                    alerts_info_response = alerts.get_alerts(ids=alert_ids)
                    status_code = response["status_code"]
                    if 200 <= alerts_info_response["status_code"] < 300:
                        alerts_info = alerts_info_response["body"]["resources"]
                        for alert in alerts_info:
                            filtered_alert = {key: alert[key] if key in alert else None for key in self.alert_fields}
                            filtered_alert_list.append(filtered_alert)
                    else:
                        return self.error(f"Something went wrong when getting device alerts {alerts_info_response['body']['errors']}")
                return self.report({"message": filtered_alert_list})
            except Exception as e:
                    self.unexpectedError(e)
        else:
            self.notSupported()

    def summary(self, raw):
        taxonomies = []
        level = "safe"
        namespace = "CSFalcon"
        predicate = "AlertDetails"
        value = str(len(raw["message"]))
        alert_count = len(raw["message"])
        if alert_count > 0:
            level = "suspicious"
            for alert in raw["message"]:
                if alert["severity"] >= 50:
                    level = "suspicious"

        # Build summary
        taxonomies.append(
            self.build_taxonomy(
                level, namespace, predicate, value
            )
        )
        return {"taxonomies": taxonomies}
    
    def artifacts(self, raw):
        artifacts = []
        return artifacts

    
if __name__ == "__main__":
    CrowdstrikeFalcon_getDeviceAlerts().run()
