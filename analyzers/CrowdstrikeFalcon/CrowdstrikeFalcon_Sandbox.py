#!/usr/bin/env python3
# encoding: utf-8
from os.path import basename
from cortexutils.analyzer import Analyzer
from falconpy import FalconXSandbox, SampleUploads,  OAuth2
import time



class CrowdstrikeFalcon_Sandbox(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        # filename of the observable
        self.filename = self.getParam("attachment.name", "noname.ext")
        self.filepath = self.getParam("file", None, "File is missing")
        self.client_id = self.get_param("config.client_id")
        self.client_secret = self.get_param("config.client_secret")
        self.base_url = self.get_param("config.base_url", "https://api.crowdstrike.com")
        self.environment = self.get_param("config.service", 160)
        self.network_settings = self.get_param("config.network_settings", "default")
        self.action_script = self.get_param("config.action_script", "default")

    def run(self):
        Analyzer.run(self)

        # file analysis
        if self.data_type == 'file':
            filepath = self.get_param('file', None, 'File is missing')
            filename = self.get_param('filename', basename(filepath))
            comment = f"Submitted from TheHive"
            # additional_params = {
            #     "action_script": "default",
            #     "command_line": "",
            #     "document_password": "",
            #     "environment_id": 160,
            #     "network_settings": "default",
            #     "send_email_notifications": False,
            #     "submit_name": filename,
            #     "submit_date": "2024-08-01",
            #     "submit_time": "12:00:00",
            #     "user_tags": ["test", "sample"]
            # }

            additional_params = {
                "environment_id": self.environment,
                "submit_name": filename,
                "network_settings": self.network_settings,
                "action_script": self.action_script
            }

            with open(filepath, "rb") as sample:
                auth = OAuth2(client_id=self.client_id, client_secret=self.client_secret, base_url=self.base_url)
                # Define the custom header
                extra_headers = {
                    "User-Agent": "strangebee-thehive/1.0"
                }
                samples = SampleUploads(auth_object=auth, ext_headers=extra_headers)
                sandbox = FalconXSandbox(auth_object=auth, ext_headers=extra_headers)
                response = samples.upload_sample(file_data=sample.read(),
                                file_name=filename,
                                comment=comment,
                                is_confidential=True
                                )
                #response = falconx.query_sample()

                #response = falconx.submit(file_name=filename, file_data=sample, **additional_params)

            # Check the response
            if response["status_code"] in [200, 201] :
                #message = f"File uploaded successfully! Submission ID : {response['body']["resources"]}"
                sha256 = response['body']["resources"][0]["sha256"]
                submit_response = sandbox.submit(body={
                    "sandbox": [{
                        "sha256": sha256,
                        **additional_params
                    }]
                })

                message = f"File submitted successfully for ! Submission ID : {submit_response}"
                
                ## Check status of on-going scan
                status = "running"
                while status == "running":
                    submit_id = submit_response["body"]["resources"][0]["id"]
                    scan_status = sandbox.get_submissions(ids=submit_id)
                    if scan_status["body"]["resources"]:
                        status = scan_status["body"]["resources"][0]["state"]

                analysis_result = sandbox.get_reports(ids=submit_id)
                message = analysis_result['body']
            else:
                self.error(f"Error uploading file: {response} and {filepath} and {sample} and {filename}")
            self.report(message)
        else:
            self.error("Datatype is not file")

    def summary(self, raw):
        taxonomies = []

        level = "info"
        namespace = "CSFalcon"
        predicate = "Sandbox"

        value = raw["resources"][0]["verdict"]

        if value == "suspicious":
            level = "suspicious"
        elif value == "malicious":
            level = "malicious"
        elif value == "no specific threat":
            level = "safe"

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
    CrowdstrikeFalcon_Sandbox().run()
