#!/usr/bin/env python3
# Author: @cyber_pescadito & @tha_cert

import json
import ssl
from cortexutils.analyzer import Analyzer
from ldap3 import Server, Connection, Tls, SIMPLE, SYNC, SUBTREE, ALL
from re import search

class LdapQuery(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        ldap_address = self.get_param(
            "config.LDAP_address", None, "ldap_address is missing"
        )
        ldap_port = self.get_param("config.LDAP_port", None, "ldap_port is missing")
        ldap_port = int(ldap_port)

        username = self.get_param("config.LDAP_username", None, "username is missing")
        password = self.get_param("config.LDAP_password", None, "password is missing")
        self.base_dn = self.get_param("config.base_DN", None, "base_dn is missing")
        self.attributes = self.get_param("config.attributes", None, "Missing attributes list to report")

        # Set search fileds and filters, related to artifact's type
        if self.data_type == "mail":
            self.search_fields = self.get_param("config.mail_search_fields", None, "mail_search_fields is missing")
            self.filters = self.get_param("config.mail_search_filter", None)
        else:
            self.search_fields = self.get_param("config.uid_search_fields", None, "uid_search_fields is missing")
            self.filters = self.get_param("config.uid_search_filter", None)
        # Prevent 'None' values and empty list
        if isinstance(self.filters, list):
            while None in self.filters:
                self.filters.remove(None)
            if len(self.filters) == 0:
                self.filters = None

        # Set auto import parameters
        self.autoimport_artifacts =  self.get_param("config.autoimport_artifacts", False)
        # Get attributes to export as observables
        self.attributes_to_extract, self.attributes_to_extract_types = self.get_attribute_mapping("config.attributes_to_extract")
        # Get attributes to export as tags
        self.attributes_to_tags, self.attributes_to_tags_prefix = self.get_attribute_mapping("config.attributes_to_tags")
        # Get attributes to export as custom fields
        self.attributes_to_custom_fields, self.attributes_to_custom_fields_prefix = self.get_attribute_mapping("config.attributes_to_custom_fields")

        # Establish LDAP server connexion
        try:
            # tls_configuration = Tls(
            #     validate=ssl.CERT_REQUIRED,
            #     version=ssl.PROTOCOL_TLSv1_2 # Or Version 1.3 if supported.
            # )
            s = Server(
                ldap_address,
                port=ldap_port,
                get_info=ALL,
                use_ssl=True if ldap_port == 636 else False,
                # tls=tls_configuration if ldap_port == 636 else None,
            )
            self.connection = Connection(
                s,
                auto_bind=True,
                client_strategy=SYNC,
                user=username,
                password=password,
                authentication=SIMPLE,
                check_names=True,
            )
        except Exception as e:
            self.error("Error during LDAP connection: %s" % e)


    def get_attribute_mapping(self, config_param):
        attributes = []
        mapped_values = []
        for item in self.get_param(config_param, []):
            if isinstance(item, str):
                split_item = item.split(':')
                attributes.append(split_item[0])
                if split_item[-1] == "": # To handle "mail:" the same way as "mail:mail" or "mail"
                    mapped_values.append(split_item[0])
                else:
                    mapped_values.append(split_item[-1])
        return attributes, mapped_values


    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "LDAP"
        predicate = "Query"

        # Summary for filtered results
        if raw.get("filtered", None):
            taxonomies.append(self.build_taxonomy("suspicious", namespace, predicate, "filtered"))
            return {"taxonomies": taxonomies}
        # Summary for empty results
        if raw.get("results", None) == []:
            taxonomies.append(self.build_taxonomy("malicious", namespace, predicate, "no_result"))
            return {"taxonomies": taxonomies}

        # Find a value to return in value attribute of taxonomies object
        for user in raw["results"]:
            if user.get("cn", None):
                value = user["cn"]
            elif user.get("mail", None):
                value = user["mail"]
            elif user.get("uid", None):
                value = user["uid"]
            else:
                value = "success"

            taxonomy = self.build_taxonomy(level, namespace, predicate, value)
            if taxonomy not in taxonomies:
                taxonomies.append(taxonomy)

        return {"taxonomies": taxonomies}


    def run(self):
        # Checking connection to LDAP
        Analyzer.run(self)
        data = self.get_param("data", None, "Data is missing")

        # Check if data should be filtered
        if self.filters:
            to_filter = True # filtered by default

            # Define data to compare with whitelist
            if self.data_type == "mail":
                data_to_check = data.split('@')[-1]
            else:
                data_to_check = data

            # Iterate on filters
            for pattern in self.filters:
                if isinstance(pattern, str) and search(pattern, data_to_check) is not None:
                    to_filter = False # If whitelist match is found: not filtered

            # Apply filtering
            if to_filter:
                if self.data_type == "mail":
                    message = "Observable value has been filtered, because domain name is not matching whitelist"
                else:
                    message = "Observable value has been filtered, because data is not matching whitelist"
                # Return filter info
                self.report({"filtered": {
                    "message": message,
                    "data": data,
                    "data_type": self.data_type,
                    "whitelist": self.filters
                    }})
                return

        try:
            # Set query
            q = "(|"
            for field in self.search_fields:
                q += "({}={})".format(field, data)
            q += ")"

            # Send LDAP request
            self.connection.search(self.base_dn, q, SUBTREE, attributes=self.attributes)
            responses = self.connection.response

            users = []
            if responses:
                for response in responses:
                    dict_response = response.get("attributes", None)
                    user = {}
                    if dict_response:
                        for att in dict_response.keys():
                            attribute = dict_response[att]
                            # Skip empty attributes
                            if attribute == "" or \
                               attribute == [] or \
                               attribute is None: continue

                            # Converting attribute in list format to comma-separated string
                            value = ""
                            if isinstance(attribute, list):
                                for i in range(len(attribute)):
                                    if i == 0: value += str(attribute[i])
                                    else: value += ", " + str(attribute[i])
                            else:
                                value = str(attribute)

                            user[att] = value
                        users.append(user)

            self.connection.unbind()

            self.report({"results": users})
        except Exception as e:
            self.error(str(e))


    def artifacts(self, raw):
        artifacts = []

        for user in raw.get("results", []):
            tags = []
            tags.append("from:" + self.get_param("data")) # Add source data tag

            # If set, add auto-import tags
            if self.autoimport_artifacts: tags.append("autoImport:true")

            # First loop necessary to get all associated tags to add during artifact creation
            for att in user.keys():
                if att in self.attributes_to_tags:
                    index = self.attributes_to_tags.index(att)
                    tags.append(self.attributes_to_tags_prefix[index] + ":" + str(user.get(att, None)))

            # Second loop to create artifacts
            for att in user.keys():
                # Skip self value
                if user.get(att, "") == self.get_param("data", None, "Data is missing"):
                    continue
                # Add artifacts
                if att in self.attributes_to_extract:
                    index = self.attributes_to_extract.index(att)
                    artifacts.append(self.build_artifact(self.attributes_to_extract_types[index], user.get(att, None), tags=tags))

        return artifacts


    def operations(self, raw):
        operations = []

        # Tag to add for filtered results
        if raw.get("filtered", None):
            operations.append(self.build_operation('AddTagToArtifact', tag="ldap_filtered"))
            return operations

        # Tags to add to returned results
        index_prefix = ""
        i = 0
        for user in raw.get("results", []):
            if i > 0: index_prefix = "(" + str(i) + ")" # Prefix used in case multiple entries are returned
            for att in user.keys():
                if att in self.attributes_to_tags: # Add tags
                    index = self.attributes_to_tags.index(att)
                    operations.append(self.build_operation('AddTagToArtifact', tag=self.attributes_to_tags_prefix[index] + index_prefix + ":" + str(user.get(att, None))))
                if att in self.attributes_to_custom_fields: # Add Custom Fileds
                    index = self.attributes_to_custom_fields.index(att)
                    operations.append(self.build_operation('AddCustomFields', name=self.attributes_to_custom_fields_prefix[index]+":"+str(user.get(att, None)), value=str(user.get(att, None)), tpe="string"))
            i += 1

        # Tag indicating analyzer's execution result
        if len(raw.get("results", [])) > 0:
            operations.append(self.build_operation('AddTagToArtifact', tag="ldap_ok"))
        else:
            operations.append(self.build_operation('AddTagToArtifact', tag="ldap_no_result"))

        return operations


if __name__ == "__main__":
    LdapQuery().run()
