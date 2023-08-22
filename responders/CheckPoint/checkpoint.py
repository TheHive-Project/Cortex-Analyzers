#!/usr/bin/env python3
# encoding: utf-8
import os
import json
import ipaddress
from cortexutils.responder import Responder
from cpapi import APIClient, APIClientArgs


class CheckPoint(Responder):
    def __init__(self):
        Responder.__init__(self)
        # Mail settings
        server = self.get_param("config.server", None, "Missing server in config")
        self.username = self.get_param(
            "config.username", None, "Missing username in config"
        )
        self.password = self.get_param(
            "config.password", None, "Missing password in config"
        )
        try:
            fingerprint_path = "{}/fingerprints.txt".format(os.path.dirname(__file__))
            fingerprint = json.loads(open(fingerprint_path, "r").read())[server]
            self.client_args = APIClientArgs(server=server, fingerprint=fingerprint)
        except:
            self.error(
                "Fingerprint check failed. It should be locate here {}".format(
                    fingerprint_path
                )
            )

        self.service = self.get_param("config.service", None)
        self.group_name = self.get_param(
            "config.group_name", None, "Missing group_name in config"
        )
        self.exclusions = self.get_param("config.exclusions", [])
        self.added_tag = self.get_param("config.added_tag", None)
        self.removed_tag = self.get_param("config.removed_tag", None)

    def run(self):
        Responder.run(self)

        data = self.get_param("data.data")
        try:
            data = ipaddress.ip_address(data)
        except ValueError:
            self.error("{} is not a valid ip".format(data))

        for excl in self.exclusions:
            try:
                excl = ipaddress.ip_address(excl)
                if data == excl:
                    self.error("{} in exclusions".format(data))
            except ValueError:
                try:
                    excl = ipaddress.ip_network(excl)
                    if data in excl:
                        self.error("{} in exclusions".format(data))
                except ValueError:
                    continue

        data = str(data)

        return_dict = {}

        with APIClient(self.client_args) as client:
            login = client.login(self.username, self.password)

            if not login.success:
                self.error("Login failed!")

            if self.service == "lock":

                # Check if group exists
                get_group_response = client.api_call(
                    "show-group", {"name": self.group_name}
                )

                if not get_group_response.success:
                    # if no create it
                    add_group_response = client.api_call(
                        "add-group", {"name": self.group_name}
                    )

                    if not add_group_response.success:
                        self.error(
                            "Error during group creation: {}".format(
                                add_group_response.error_message
                            )
                        )
                    else:
                        client.api_call("publish", {})
                        return_dict["group_created"] = True
                else:
                    return_dict["group_created"] = False

                # Check if host exists
                get_host_response = client.api_call("show-host", {"name": data})

                if not get_host_response.success:
                    return_dict["host_created"] = True

                    # Create host from ip
                    add_host_response = client.api_call(
                        "add-host",
                        {
                            "name": data,
                            "ip-address": data,
                            "comments": "From TheHive responder",
                        },
                    )

                    if not add_host_response.success:
                        self.error(
                            "Error during host creation: {}".format(
                                add_host_response.error_message
                            )
                        )
                else:
                    client.api_call("publish", {})
                    return_dict["host_created"] = False

                # Add observable to group
                response = client.api_call(
                    "set-group",
                    {"name": self.group_name, "members": {"add": data}},
                )

                if not response.success:
                    self.error(
                        "Error adding host to group: {}".format(response.error_message)
                    )
                else:
                    # COMMIT CHANGES
                    client.api_call("publish", {})
                    return_dict["Success"] = True

            elif self.service == "unlock":
                # Check if host exists
                get_host_response = client.api_call("show-host", {"name": data})

                if not get_host_response.success:
                    self.error(
                        "Host doen't exists: {}".format(get_host_response.error_message)
                    )

                # Remove observable from group
                response = client.api_call(
                    "set-group",
                    {"name": self.group_name, "members": {"remove": data}},
                )

                if not response.success:
                    self.error(
                        "Error removing host from group: {}".format(
                            response.error_message
                        )
                    )
                else:
                    # COMMIT CHANGES
                    client.api_call("publish", {})
                    return_dict["Success"] = True

            self.report({"message": return_dict})

    def operations(self, raw):
        if self.service == "lock" and self.added_tag:
            return [self.build_operation("AddTagToArtifact", tag=self.added_tag)]
        elif self.service == "unlock" and self.removed_tag:
            return [self.build_operation("AddTagToArtifact", tag=self.removed_tag)]


if __name__ == "__main__":
    CheckPoint().run()
