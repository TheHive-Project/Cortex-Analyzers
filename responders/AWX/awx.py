#!/usr/bin/env python3
from cortexutils.responder import Responder
import requests
import json

class AWX(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.url = self.get_param("config.url", "")
        self.username = self.get_param("config.username","")
        self.password = self.get_param("config.password","")
        self.workflow_id = self.get_param("config.workflow_id", "")
        self.observable_all = self.get_param('data', None, 'Data missing!')
        self.cert_path = self.get_param('config.cert_path')

    def run(self):
        Responder.run(self)
        headers = {
            'Content-Type': 'application/json'
        }
        payload = {
            'extra_vars': json.dumps(self.observable_all)
        }
        # Start the job
        job_start_endpoint = self.url + '/api/v2/job_templates/' + self.workflow_id + '/launch/'
        
        try:
            response = requests.post(
                job_start_endpoint,
                headers=headers,
                auth=(self.username, self.password),
                data=json.dumps(payload),
                verify=self.cert_path if self.cert_path else False
            )

            response.raise_for_status()

            if response.status_code == 201:
                self.report({"Message": "Executed AWX job successfully"})
            else:
                error_msg = response.json().get('detail', 'Unknown error')
                self.error(f"AWX job execution returned unexpected status {response.status_code}: {error_msg}")
        except requests.exceptions.SSLError as ssl_err:
            self.error(f"SSL Error: {str(ssl_err)}")
        except requests.exceptions.ConnectionError as conn_err:
            self.error(f"Connection Error: {str(conn_err)}")
        except requests.exceptions.Timeout as timeout_err:
            self.error(f"Request Timeout: {str(timeout_err)}")
        except requests.exceptions.RequestException as req_err:
            try:
                # Try to get additional details from the JSON response
                error_details = response.json().get('detail', 'No additional error details available.')
            except json.JSONDecodeError:
                error_details = 'Failed to parse error details from response.'
            
            self.error(f"Request Error: {str(req_err)} - Details: {error_details}")
        except Exception as unexpected_err:
            self.error(f"Unexpected Error: {str(unexpected_err)}")


if __name__ == '__main__':
    AWX().run()
