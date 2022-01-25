#!/usr/bin/env python3
# Author: @cyber_pescadito
import json
from cortexutils.analyzer import Analyzer
import ldap3
from ldap3 import Server, Connection, SIMPLE, SYNC, SUBTREE, ALL


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
        uid_search_field = self.get_param(
            "config.uid_search_field", None, "uid_search_field is missing"
        )
        if self.data_type == "mail":
            self.search_field = "mail"
        else:
            self.search_field = uid_search_field

        self.attributes = self.get_param(
            "config.attributes", None, "Missing attributes list to report"
        )
        try:
            s = Server(
                ldap_address,
                port=ldap_port,
                get_info=ALL,
                use_ssl=True if ldap_port == 636 else False,
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
        except Exception:
            self.error("Error during LDAP connection")

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "LDAP"
        predicate = "Query"

        # Find a value to return in value attribute of taxonomies object
        for user in raw["results"]:
            if user.get("o", None):
                value = user["o"]
            elif user.get("cn", None):
                value = user["cn"]
            elif user.get("mail", None):
                value = user["mail"]
            else:
                value = "success"

            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        # Checking connection to LDAP
        Analyzer.run(self)
        try:

            data = self.get_param("data", None, "Data is missing")
            q = "({}={})".format(self.search_field, data)

            self.connection.search(self.base_dn, q, SUBTREE, attributes=self.attributes)
            responses = self.connection.response

            users = []
            if responses:
                for response in responses:
                    dict_response = response.get("attributes", None)
                    user = {}
                    if dict_response:
                        for att in dict_response.keys():
                            user[att] = dict_response[att]
                        users.append(user)

            self.connection.unbind()

            self.report({"results": users})
        except Exception as e:
            self.error(str(e))


if __name__ == "__main__":
    LdapQuery().run()
