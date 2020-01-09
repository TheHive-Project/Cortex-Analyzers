#!/usr/bin/env python
#Author: @cyber_pescadito
import ldap
import json
from cortexutils.analyzer import Analyzer

class LdapQuery(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.ldap_address = self.get_param('config.LDAP_Server_Address', None, 'ldap_address is missing')
        self.username = self.get_param('config.LDAP_Username', None, 'username is missing')
        self.password = self.get_param('config.LDAP_Password', None, 'password is missing')
        self.base_dn = self.get_param('config.base_DN', None, 'base_dn is missing')
        self.attributes = self.get_param('config.Attributes', None, 'Missing attributes list to report')
        self.payload = self.get_param('data', None, 'username to search in LDAP is missing')

    def summary(self,raw,taxonomies_value):
        taxonomies = []
        level = "info"
        namespace = "LDAP"
        predicate = "Query"
        value = taxonomies_value
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        #Checking connection to LDAP
        Analyzer.run(self)
        try:
            l=ldap.initialize(self.ldap_address)
            l.protocol_version = ldap.VERSION3
            l.simple_bind_s(self.username, self.password)
            valid = True
        except ldap.LDAPError, e:
            self.error(e)
        #Searching for the user
        try:
            searchScope = ldap.SCOPE_SUBTREE
            if self.data_type == "username":
                searchFilter = "(uid=" + self.payload + ")"
            elif self.data_type == "mail":
                searchFilter = "(mail=" + self.payload + ")"
            else:
                self.error('observable type not supported by this analyzer.')
            ldap_result_id = l.search(self.base_dn, searchScope, searchFilter, self.attributes)
            result_set = []
            queryResult = {}
            while 1:
                result_type, result_data = l.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                else:
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        result_set.append(result_data)
            for attribute in self.attributes:
                try:
                    queryResult[attribute] = result_set[0][0][1][attribute][0]
                except:
                    queryResult[attribute] = "unknown"
#           Cleaning characters that are wrongly parsed in thehive templates
            for key in queryResult:
                str=key
                strnew=str.replace('-','_')
                queryResult[strnew]=queryResult.pop(str)

#           Find a value to return in value attribute of taxonomies object
            if o in queryResult:
                taxonomies_value = str(queryResult[o])
            else if cn in queryResult:
                taxonomies_value = str(queryResult[cn])
            else if mail in queryResult:
                taxonomies_value = str(queryResult[mail])
            else:
                taxonomies_value = "Success"
                
            json_data = queryResult
        except ldap.LDAPError, e:
            self.error(e)


        self.report(json_data)

if __name__ == '__main__':
    LdapQuery().run()
