#!/usr/bin/env python3
# encoding: utf-8

import asyncio
from cortexutils.analyzer import Analyzer
from okta.client import Client as OktaClient

class OktaUserlookupAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.url = self.get_param('config.OktaOrgUrl', None, 'Missing Okta Organisation URL')
        self.okta_token = self.get_param('config.OktaToken', None, 'Missing Okta Token')

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Okta"
        predicate = "Query"

        for key, value in raw["results"].items():
            if key in ["Country Code", "Supervisory Org", "Company"]:
                taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'mail':
            try:
                data = self.get_param("data", None, "Data is missing")
                query_parameters = {'q':f'{data}'}
                okta_client = OktaClient({'orgUrl':self.url, 'token':self.okta_token})
                async_couroutine = okta_client.list_users(query_parameters)

                response =  asyncio.run(async_couroutine)

                userData = dict()
                if response[0]:
                    udt = response[0][0]
                    userData['Activated'] = udt.activated
                    userData['City'] = udt.profile.city
                    userData['Country Code'] = udt.profile.countryCode
                    userData['Department'] = udt.profile.department
                    userData['First Name'] = udt.profile.firstName
                    userData['Last Name'] = udt.profile.lastName
                    userData['Organization'] = udt.profile.organization
                    userData['Street Address'] = udt.profile.streetAddress
                    userData['Title'] = udt.profile.title
                    if 'workerStatus' in udt.profile.as_dict().keys():
                        userData['Worker Status'] = udt.profile.workerStatus
                    userData['Identity Type'] = udt.profile.identityType
                    userData['Company'] = udt.profile.company
                    if 'on_long_leave' in udt.profile.as_dict().keys():
                        userData['On Long Leave'] = udt.profile.on_long_leave
                    if 'supervisoryOrg' in udt.profile.as_dict().keys():
                        userData['Supervisory Org'] = udt.profile.supervisoryOrg
                    userData['Status'] = udt.status.value
                    userData['Transitioning to Status'] = udt.transitioning_to_status

                self.report({"results": userData})
            except Exception as e:
                self.error(str(e))

if __name__ == '__main__':
    OktaUserlookupAnalyzer().run()
