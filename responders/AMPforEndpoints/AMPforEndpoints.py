#!/usr/bin/env python3
# encoding: utf-8

import re
import json
import requests
from cortexutils.responder import Responder


class AMPforEndpoints(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.service = self.get_param("config.service", None, "Service Missing")
        self.amp_cloud = self.get_param("config.amp_cloud", None, "AMP HOST Missing")
        self.client_id = self.get_param("config.client_id", None, "Client ID Missing")
        self.api_key = self.get_param("config.api_key", None, "API Key Missing")

        if self.service in ("scdadd", "scdremove"):
            self.scd_guid = self.get_param(
                "config.scd_guid", None, "Simple Custom Detectoin GUID Missing"
            )
        if self.service in ("moveguid"):
            self.group_guid = self.get_param(
                "config.group_guid", None, "Group GUID Missing"
            )
        if self.service in ("isolationstart"):
            self.unlock_code = self.get_param("config.unlock_code", None)

        self.amp_session = requests.Session()
        self.amp_session.auth = (self.client_id, self.api_key)
        self.amp_session.headers.update(
            {
                "User-Agent": "AMPforEndpoints-Cortex-Responder",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Accept-Encoding": "gzip, deflate",
            }
        )

    def run(self):
        def parse_amp_error(error_response):
            """Parse AMP for Endponts error response
               Return the human readable error message
            """
            try:
                response = error_response.json()
                errors = response.get("errors", [])
                details = errors[0].get("details", [])
                error = details[0]
                return error
            except IndexError:
                return "Something went wrong! Recieved status code: {}".format(
                    error_response.status_code
                )

        def validate_guid(guid):
            """Validate the provided GUIDs is the correct format
            """
            expression = r"^[A-Fa-f0-9]{8}\-[A-Fa-f0-9]{4}\-[A-Fa-f0-9]{4}\-[A-Fa-f0-9]{4}\-[A-Fa-f0-9]{12}$"
            return bool(re.match(expression, guid))

        def scd_add(amp_cloud, scd_guid, sha256, caseId, title):
            """Add a SHA256 to a Simple Custom Detection List
            """
            url = "https://{}/v1/file_lists/{}/files/{}".format(
                amp_cloud, scd_guid, sha256
            )

            body = {
                "description": "The Hive Case ID: {} Case Title: {}".format(
                    caseId, title
                )
            }
            body = json.dumps(body)
            response = self.amp_session.post(url, data=body)

            if response.status_code == 201:
                self.report({"message": "SHA256 Added to SCD"})
            if response.status_code == 409:
                self.error("SHA256 already on SCD list")
            else:
                self.error("Failed to add to blacklist.")

        def scd_remove(amp_cloud, scd_guid, sha256):
            """Remove a SHA256 from a Simple Custom Detection List
            """
            url = "https://{}/v1/file_lists/{}/files/{}".format(
                amp_cloud, scd_guid, sha256
            )

            response = self.amp_session.delete(url)

            if response.status_code == 200:
                self.report({"message": "SHA256 removed from SCD"})
            else:
                error = parse_amp_error(response)
                self.error(error)

        def move_guid(amp_cloud, group_guid, connector_guid):
            """Move a connector GUID to a new group
            """
            url = "https://{}/v1/computers/{}".format(amp_cloud, connector_guid)

            body = {"group_guid": group_guid}
            body = json.dumps(body)

            response = self.amp_session.patch(url, data=body)
            response_json = response.json()
            data = response_json.get("data", {})
            hostname = data.get("hostname", "for uknown hostname")

            if response.status_code == 202:
                self.report({"message": "Connector {} moved".format(hostname)})
            else:
                error = parse_amp_error(response)
                self.error(error)

        def isolation_start(amp_cloud, connector_guid, unlock_code):
            """Send request to start host isolation for a connector
            """
            url = "https://{}/v1/computers/{}/isolation".format(
                amp_cloud, connector_guid
            )

            if unlock_code:
                body = {"unlock_code": unlock_code}
                body = json.dumps(body)
                response = self.amp_session.put(url, data=body)
            else:
                response = self.amp_session.put(url)

            if response.status_code == 200:
                self.report(
                    {
                        "message": "Request sent to start isolation for connector: {}".format(
                            connector_guid
                        )
                    }
                )
            else:
                error = parse_amp_error(response)
                self.error(error)

        def isolation_stop(amp_cloud, connector_guid):
            """Send request to stop host isolation for a connector
            """
            url = "https://{}/v1/computers/{}/isolation".format(
                amp_cloud, connector_guid
            )

            response = self.amp_session.delete(url)

            if response.status_code == 200:
                self.report(
                    {
                        "message": "Request sent to stop isolation for connector: {}".format(
                            connector_guid
                        )
                    }
                )
            else:
                error = parse_amp_error(response)
                self.error(error)

        Responder.run(self)

        dataType = self.get_param("data.dataType")

        if dataType == "hash" and self.service in ("scdadd", "scdremove"):
            sha256 = self.get_param("data.data", None)
            caseId = self.get_param("data.case.caseId", None, "caseId is missing")
            title = self.get_param("data.case.title", None, "title is missing").encode(
                "utf-8"
            )

            # Valide a valid SHA256 was provided
            if not re.match(r"^[A-Fa-f0-9]{64}$", sha256):
                self.error("{} is not a SHA256".format(sha256))

            # Add SHA256 to Simple Custom Detection list
            if self.service == "scdadd":
                scd_add(self.amp_cloud, self.scd_guid, sha256, caseId, title)

            # Remove SHA256 from Simple Custom Detection list
            if self.service == "scdremove":
                scd_remove(self.amp_cloud, self.scd_guid, sha256)

        if dataType == "other" and self.service in (
            "moveguid",
            "isolationstart",
            "isolationstop",
        ):
            connector_guid = self.get_param("data.data", None)

            # Validate the connector GUID is the right format
            if not validate_guid(connector_guid):
                self.error(
                    "{} is not a valid AMP connector GUID".format(connector_guid)
                )

            # Validate the Group GUID is the right format
            if self.service in ("moveguid") and not validate_guid(self.group_guid):
                self.error("{} is not a valid AMP Group GUID".format(self.group_guid))

            # Move the connector GUID to a new group
            if self.service in ("moveguid"):
                move_guid(self.amp_cloud, self.group_guid, connector_guid)

            # Start host isolation
            if self.service in ("isolationstart"):
                # Check if the unlock_code is less than 24 characters
                if self.unlock_code and self.unlock_code and len(self.unlock_code) > 24:
                    self.error(
                        "Validation failed: Unlock Code is invalid, Unlock Code is too long. (Maximum 24 characters)"
                    )
                # Check if the unlock_code contains spaces
                if self.unlock_code and bool(" " in self.unlock_code):
                    self.error(
                        "Validation failed: Unlock Code is invalid, Unlock Code cannot contain spaces"
                    )
                isolation_start(self.amp_cloud, connector_guid, self.unlock_code)

            # Stop host isolation
            if self.service in ("isolationstop"):
                isolation_stop(self.amp_cloud, connector_guid)

        # Return an error for all other datatypes
        self.error(
            "Incorrect dataType received '{}' as '{}'".format(
                self.get_param("data.data", None), dataType
            )
        )

    def operations(self, raw):
        if self.service == "scdadd":
            return [self.build_operation("AddTagToArtifact", tag="AMP:blocked")]


if __name__ == "__main__":
    AMPforEndpoints().run()
