#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from ldap3 import Server, Connection, ALL, SIMPLE

class ADAuthAnalyzer(Analyzer):
    def __init__(self):
        super().__init__()
        # Gathering parameters from configurationItems defined in the JSON file
        self.ldap_address = self.get_param('config.LDAP_address')
        self.ldap_port = int(self.get_param('config.LDAP_port', 636))
        self.connection_method = self.get_param('config.Connection_Method', "SIMPLE")
        self.domain = self.get_param('config.Domain')

    def summary(self, raw):
        """
        Generate taxonomies in TheHive.
        """
        taxonomies = []

        if raw.get("auth_successful"):
            taxonomies.append(self.build_taxonomy("suspicious", "AuthTest", self.ldap_address, "Success"))
        else:
            taxonomies.append(self.build_taxonomy("safe", "AuthTest", self.ldap_address, "Login Failed"))
            
        return {"taxonomies": taxonomies}

    def run(self):
        data = self.getData()

        # 1. Split observable
        try:
            raw_username, password = data.split(":", 1)
        except ValueError:
            self.error("Invalid format. Observables need to be splitted using the format 'username:password'")

        # 2. Domain completion if the username is a SamAccountName
        if "@" in raw_username:
            username = raw_username
        else:
            username = f"{raw_username}@{self.domain}"

        # 3. LDAP authentication
        try:
            server = Server(self.ldap_address, port=self.ldap_port, get_info=ALL)
            conn = Connection(server, user=username, password=password, authentication=self.connection_method)
            
            if conn.bind():
                conn.unbind()
                self.report({
                    "auth_successful": True,
                    "input_used": raw_username,
                    "username": username,
                    "message": f"Authentication successful for {username} on {self.ldap_address}:{self.ldap_port} !"
                })
            else:
                self.report({
                    "auth_successful": False,
                    "input_used": raw_username,
                    "username": username,
                    "message": f"Authentication failed for {username} on {self.ldap_address}:{self.ldap_port}."
                })

        except Exception as e:
            self.error(f"Error connecting to LDAP server {self.ldap_address}:{self.ldap_port} - Details : {str(e)}")

if __name__ == '__main__':
    ADAuthAnalyzer().run()