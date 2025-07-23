#!/usr/bin/env python3

from cortexutils.responder import Responder
from falconpy import OAuth2, Alerts, Incidents

class CrowdstrikeFalconSync(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.client_id = self.get_param("config.client_id")
        self.client_secret = self.get_param("config.client_secret")
        self.base_url = self.get_param("config.base_url", "https://api.crowdstrike.com")
        self.service = self.get_param("config.service", None)
        self.custom_field_name_alert_id = self.get_param("config.custom_field_name_alert_id")
        self.custom_field_name_incident_id = self.get_param("config.custom_field_name_incident_id")

    def run(self):
        if self.service == "sync":
            # Define the custom headers
            extra_headers = {
                "User-Agent": "strangebee-thehive/1.0"
            }
            #data = self.get_param("data", None, "Can't get case ID")
            current_stage = self.get_param("data.stage", None, "Can't get case or alert stage")
            detection_id = self.get_param(f"data.customFieldValues.{self.custom_field_name_alert_id}", None)
            incident_id = self.get_param(f"data.customFieldValues.{self.custom_field_name_incident_id}", None)
            
            if not detection_id and not incident_id:
                self.error("No detection ID or incident ID found in the case custom fields.")

            # Map TheHive case stages to CrowdStrike alert statuses
            status_mapping_alert = {
                "New": "new",
                "InProgress": "in_progress",
                "Imported": "in_progress",
    #            "Resolved": "closed",
                "Closed": "closed"
            }
            
            # Map TheHive case stages to CrowdStrike incident statuses
            status_mapping_incident = {
                "Open": "20",         # New
                "InProgress": "30",  # In Progress
    #            "Resolved": "40",     # Closed
                "Closed": "40",       # Closed
    #            "Reopened": "25"      # Reopened
            }

            if current_stage not in status_mapping_alert:
                self.error(f"Unknown case status: {current_stage}")

            auth = OAuth2(client_id=self.client_id, client_secret=self.client_secret, base_url=self.base_url)

            # Update the CrowdStrike alert status
            if detection_id:
                alert_client = Alerts(auth_object=auth, ext_headers=extra_headers)
                # Determine the corresponding CrowdStrike alert status
                cs_status_alert = status_mapping_alert[current_stage]
                if isinstance(detection_id,str):
                    detection_id = [detection_id]
                # Update the CrowdStrike alert status using update_alerts_v3
                alert_body = {
                    "composite_ids": detection_id,
                    "action_parameters": [
                        {
                            "name": "update_status",
                            "value": cs_status_alert
                        }
                    ]
                }
                alert_response = alert_client.update_alerts_v3(body=alert_body)
                alert_status_code = alert_response.get('status_code', None)

                
            if incident_id:
                incident_client = Incidents(auth_object=auth, ext_headers=extra_headers)
                # Determine the corresponding CrowdStrike incident status
                cs_status_incident = status_mapping_incident[current_stage]
                if isinstance(incident_id,str):
                    incident_id = [incident_id]
                # Update the CrowdStrike incident status using perform_incident_action
                incident_body = {
                    "ids": incident_id,
                    "action_parameters": [
                        {
                            "name": "update_status",
                            "value": cs_status_incident
                        }
                    ]
                }

                incident_response = incident_client.perform_incident_action(body=incident_body)
                incident_status_code = incident_response.get('status_code', None)


            # Combine responses into a single message
            messages = []

            if detection_id:
                if 200 <= alert_status_code < 300:
                    messages.append(f"Successfully updated CrowdStrike alert(s): {detection_id} to status '{cs_status_alert}'.")
                else:
                    messages.append(f"Failed to update alert(s): {alert_response.get('body', 'No additional error information available')}.")

            if incident_id:
                if 200 <= incident_status_code < 300:
                    messages.append(f"Successfully updated CrowdStrike incident(s): {incident_id} to status '{cs_status_incident}'.")
                else:
                    messages.append(f"Failed to update incident(s): {incident_response.get('body', 'No additional error information available')}.")

            # Check if any operation failed
            final_message = " | ".join(messages)

            if "Failed" in final_message:
                self.error(f"Errors encountered: {final_message}")
            else:
                self.report({"message": final_message})

if __name__ == '__main__':
    CrowdstrikeFalconSync().run()
