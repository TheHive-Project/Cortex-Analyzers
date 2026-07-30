#!/usr/bin/env python3
from cortexutils.responder import Responder
import requests
import datetime
import string

# https://learn.microsoft.com/en-us/defender-endpoint/indicators-overview
IP_HOSTNAME_ACTIONS = [
  'isolateMachine',
  'unisolateMachine',
  'runFullVirusScan',
  'restrictAppExecution',
  'unrestrictAppExecution',
  'startAutoInvestigation'
]
URL_DOMAIN_ACTIONS = [
  'pushIOCAllowed',
  'pushIOCAudit',
  'pushIOCWarn',
  'pushIOCBlock'
]

ACTIONS = {
  'hash': URL_DOMAIN_ACTIONS + ['pushIOCBlockAndRemediate', 'stopAndQuarantineFile'],
  'ip': URL_DOMAIN_ACTIONS + IP_HOSTNAME_ACTIONS,
  'url': URL_DOMAIN_ACTIONS,
  'domain': URL_DOMAIN_ACTIONS,
  'fqdn': URL_DOMAIN_ACTIONS,
  'hostname': IP_HOSTNAME_ACTIONS,
}

# MDE tokens must be issued for the legacy "securitycenter" resource even when
# calling the api.security.microsoft.com host, otherwise requests fail with
# 403 Forbidden. See "Get an access token" in:
# https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp
TOKEN_SCOPE = "https://api.securitycenter.microsoft.com/.default"

class MSDefenderForEndpoint(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.tenant_id = self.get_param('config.tenantId', None, 'TenantId missing!')
        self.app_id = self.get_param('config.appId', None, 'AppId missing!')
        self.app_secret = self.get_param('config.appSecret', None, 'AppSecret missing!')
        self.resource_app_id_uri = self.get_param(
            'config.resourceAppIdUri', None, 'resourceAppIdUri missing!'
        )
        self.oauth_uri = self.get_param('config.oAuthUri', None, 'oAuthUri missing!')
        self.api_base_url = self.resource_app_id_uri.rstrip('/') + "/api/v1.0"
        self.observable = self.get_param('data.data', None, "Data is empty")
        self.observable_type = self.get_param('data.dataType', None, "Data type is empty")
        self.case_id = self.get_param("data.case.caseId", None, "caseId is missing")
        self.case_title = self.get_param('data.case.title', None, 'Case title is missing')
        self.service = self.get_param("config.service", None, "Service Missing")

        self.session = requests.Session()
        self.session.headers.update(
            {
                'Accept' : 'application/json',
                'Content-Type' : 'application/json'
            }
        )

    def run(self):
        Responder.run(self)
        url = "{}/{}/oauth2/v2.0/token".format(
            self.oauth_uri,self.tenant_id
            )

        body = {
            'scope' : TOKEN_SCOPE,
            'client_id' : self.app_id,
            'client_secret' : self.app_secret,
            'grant_type' : 'client_credentials'
        }

        try:
            response = requests.post(url, data=body, timeout=30)
        except requests.exceptions.RequestException as e:
            self.error(
                "Unable to reach Azure AD login endpoint: {}".format(str(e))
            )

        if response.status_code != 200:
            self.error(
                "Azure AD auth failed (HTTP {}): {}".format(
                    response.status_code, response.text
                )
            )

        token = response.json().get("access_token")
        if not token:
            self.error("Azure AD auth response missing access token")

        self.session.headers.update(
            {
                'Authorization' : 'Bearer {0}'.format(token)
            }
        )

        def get_machine_id(id):
            time = datetime.datetime.now() - datetime.timedelta(minutes=60)
            time = time.strftime("%Y-%m-%dT%H:%M:%SZ")

            if self.observable_type == "ip":
                url = "{}/machines/findbyip(ip='{}',timestamp={})".format(
                    self.api_base_url, id, time
                )
            elif self.observable_type == "hostname":
                url = "{}/machines?$filter=computerDnsName+eq+'{}'".format(
                    self.api_base_url, id
                )
            else:
                self.error(
                    f"Data type {self.observable_type} not supported, "
                    f"accepted types are: 'ip', 'hostname'."
                )

            try:
                response = self.session.get(url=url, timeout=30)
                if response.status_code == 200:
                    json_response = response.json()
                    if len(response.content) > 100:
                        return json_response["value"][0]["id"]
                    else:
                        self.error("Can't get hostname from Microsoft API")
                else:
                    self.error(
                        "Can't get machine from Microsoft API "
                        "(HTTP {})".format(response.status_code)
                    )
            except requests.exceptions.RequestException as e:
                self.error(str(e))

        def isolate_machine(machineId):
            '''
            example
            POST {api_base_url}/machines/{id}/isolate
            '''
            url = '{}/machines/{}/isolate'.format(self.api_base_url, machineId)

            body = {
                'Comment': 'Isolate machine due to TheHive case {}'.format(self.case_id),
                'IsolationType': 'Full'
                }

            try:
                response = self.session.post(url=url, json=body, timeout=30)
                if response.status_code == 201:
                    self.report({'message': "Isolated machine: " + self.observable})
                elif (
                    response.status_code == 400
                    and "ActiveRequestAlreadyExists" in response.content.decode("utf-8")
                ):
                    self.report({
                        'message': "Error isolating machine: ActiveRequestAlreadyExists"
                    })
                else:
                    self.error(
                        "Can't isolate machine (HTTP {}): {}".format(
                            response.status_code, response.text
                        )
                    )
            except requests.exceptions.RequestException as e:
                self.error(str(e))

        def run_full_virus_scan(machineId):
            '''
            example
            POST {api_base_url}/machines/{id}/runAntiVirusScan
            '''
            url = '{}/machines/{}/runAntiVirusScan'.format(self.api_base_url, machineId)

            body = {
                'Comment': 'Full scan due to TheHive case {}'.format(self.case_id),
                'ScanType': 'Full'
                }

            try:
                response = self.session.post(url=url, json=body, timeout=30)
                if response.status_code == 201:
                    self.report({
                        'message': "Started full VirusScan on machine: " + self.observable
                    })
                elif (
                    response.status_code == 400
                    and "ActiveRequestAlreadyExists" in response.content.decode("utf-8")
                ):
                    self.report({
                        'message': "Error full VirusScan: ActiveRequestAlreadyExists"
                    })
                else:
                    self.error(
                        "Error full VirusScan (HTTP {}): {}".format(
                            response.status_code, response.text
                        )
                    )
            except requests.exceptions.RequestException as e:
                self.error(str(e))


        def unisolate_machine(machineId):
            '''
            example
            POST {api_base_url}/machines/{id}/unisolate
            '''
            url = '{}/machines/{}/unisolate'.format(self.api_base_url, machineId)
            body = {
                'Comment': 'Unisolate machine due to TheHive case {}'.format(self.case_id)
                }

            try:
                response = self.session.post(url=url, json=body, timeout=30)
                if response.status_code == 201:
                    self.report({'message': "Unisolated machine: " + self.observable})
                elif (
                    response.status_code == 400
                    and "ActiveRequestAlreadyExists" in response.content.decode("utf-8")
                ):
                    self.report({
                        'message': "Error unisolating machine: ActiveRequestAlreadyExists"
                    })
                else:
                    self.error(
                        "Can't unisolate machine (HTTP {}): {}".format(
                            response.status_code, response.text
                        )
                    )
            except requests.exceptions.RequestException as e:
                self.error(str(e))


        def restrict_app_execution(machineId):
            '''
            example
            POST {api_base_url}/machines/{id}/restrictCodeExecution
            '''
            url = '{}/machines/{}/restrictCodeExecution'.format(
                self.api_base_url, machineId
            )
            body = {
                'Comment': 'Restrict code execution, case {}'.format(self.case_id)
                }

            try:
                response = self.session.post(url=url, json=body, timeout=30)
                if response.status_code == 201:
                    self.report({
                        'message': "Restricted app execution on: " + self.observable
                    })
                elif (
                    response.status_code == 400
                    and "ActiveRequestAlreadyExists" in response.content.decode("utf-8")
                ):
                    self.report({
                        'message': "Error restricting app execution: "
                                   "ActiveRequestAlreadyExists"
                    })
                else:
                    self.error(
                        "Can't restrict app execution (HTTP {}): {}".format(
                            response.status_code, response.text
                        )
                    )
            except requests.exceptions.RequestException as e:
                self.error(str(e))


        def unrestrict_app_execution(machineId):
            '''
            example
            POST {api_base_url}/machines/{id}/unrestrictCodeExecution
            '''
            url = '{}/machines/{}/unrestrictCodeExecution'.format(
                self.api_base_url, machineId
            )
            body = {
                'Comment': (
                    'Remove code execution restriction: machine cleaned and validated, '
                    'case {}'
                ).format(self.case_id)
                }

            try:
                response = self.session.post(url=url, json=body, timeout=30)
                if response.status_code == 201:
                    self.report({
                        'message':
                            "Removed app execution restriction on machine: "
                            + self.observable
                    })
                elif (
                    response.status_code == 400
                    and "ActiveRequestAlreadyExists" in response.content.decode("utf-8")
                ):
                    self.report({
                        'message':
                            "Error removing app execution restriction: "
                            "ActiveRequestAlreadyExists"
                    })
                else:
                    self.error(
                        "Can't unrestrict app execution (HTTP {}): {}".format(
                            response.status_code, response.text
                        )
                    )
            except requests.exceptions.RequestException as e:
                self.error(str(e))


        def start_auto_investigation(machineId):
            '''
            example
            POST {api_base_url}/machines/{id}/startInvestigation
            '''
            url = '{}/machines/{}/startInvestigation'.format(self.api_base_url, machineId)

            body = {
                'Comment': 'Start investigation, case {}'.format(self.case_id)
                }

            try:
                response = self.session.post(url=url, json=body, timeout=30)
                if response.status_code == 201:
                    self.report({
                        'message': "Started Auto Investigation on: " + self.observable
                    })
                elif (
                    response.status_code == 400
                    and "ActiveRequestAlreadyExists" in response.content.decode("utf-8")
                ):
                    self.report({
                        'message': "Error launching auto investigation: "
                                   "ActiveRequestAlreadyExists"
                    })
                else:
                    self.error(
                        "Error auto investigation (HTTP {}): {}".format(
                            response.status_code, response.text
                        )
                    )
            except requests.exceptions.RequestException as e:
                self.error(str(e))


        def push_custom_ioc(observable, mode='Block', severity='Medium', alert=True):
            if self.observable_type == 'ip':
                indicator_type = 'IpAddress'
            elif self.observable_type == 'url':
                indicator_type = 'Url'
            elif self.observable_type in ('domain', 'fqdn'):
                indicator_type = 'DomainName'
            elif self.observable_type == 'hash':
                if not all(c in string.hexdigits for c in observable):
                    self.error("Observable is not a valid hash")
                elif len(observable) == 32:
                    indicator_type = 'FileMd5'
                elif len(observable) == 40:
                    indicator_type = 'FileSha1'
                elif len(observable) == 64:
                    indicator_type = 'FileSha256'
                else:
                    self.error("Observable is not a valid hash")
            else:
                self.error(
                    "Observable type must be 'ip', 'url', 'domain', "
                    "'fqdn' or 'hash'"
                )

            url = '{}/indicators'.format(self.api_base_url)
            body = {
                'indicatorValue': observable,
                'indicatorType': indicator_type,
                'action': mode,
                'title': "TheHive IOC: {}".format(self.case_title),
                'severity': severity,
                'description': "TheHive case: {} - caseId {}".format(
                    self.case_title, self.case_id
                ),
                'recommendedActions': 'N/A',
                'generateAlert': alert
            }

            try:
                response = self.session.post(url=url, json=body, timeout=30)
                if response.status_code == 200:
                    self.report({
                        'message': "Added IOC to Defender with %s mode: " % mode
                                   + self.observable
                    })
                else:
                    self.error(
                        "Can't add IOC to Defender (HTTP {})".format(
                            response.status_code
                        )
                    )
            except requests.exceptions.RequestException as e:
                self.error(str(e))


        def stop_and_quarantine_file(observable):
            '''
            example
            GET {api_base_url}/files/{sha1}/machines
            POST {api_base_url}/machines/{id}/StopAndQuarantineFile
            Only SHA1 is supported by both endpoints (not MD5 or SHA256).
            '''
            is_sha1 = (
                len(observable) == 40
                and all(c in string.hexdigits for c in observable)
            )
            if not is_sha1:
                self.error(
                    "Stop and quarantine file requires a SHA1 hash "
                    "(40 hex chars)"
                )

            machines_url = '{}/files/{}/machines'.format(self.api_base_url, observable)
            try:
                response = self.session.get(url=machines_url, timeout=30)
            except requests.exceptions.RequestException as e:
                self.error(str(e))

            if response.status_code != 200:
                self.error(
                    "Can't get machines for file (HTTP {})".format(
                        response.status_code
                    )
                )

            machines = response.json().get('value', [])
            if not machines:
                self.error("No machine found with this file: " + observable)

            results = []
            for machine in machines:
                machine_id = machine.get('id')
                url = '{}/machines/{}/StopAndQuarantineFile'.format(
                    self.api_base_url, machine_id
                )
                body = {
                    'Comment': 'Stop and quarantine file, case {}'.format(self.case_id),
                    'Sha1': observable
                    }

                try:
                    machine_response = self.session.post(url=url, json=body, timeout=30)
                    if machine_response.status_code == 201:
                        results.append("{}: quarantined".format(machine_id))
                    elif (
                        machine_response.status_code == 400
                        and "ActiveRequestAlreadyExists" in
                        machine_response.content.decode("utf-8")
                    ):
                        results.append(
                            "{}: ActiveRequestAlreadyExists".format(machine_id)
                        )
                    else:
                        results.append("{}: failed (HTTP {})".format(
                            machine_id, machine_response.status_code
                        ))
                except requests.exceptions.RequestException as e:
                    results.append("{}: error {}".format(machine_id, str(e)))

            self.report({
                'message': "Stop and quarantine file {} on {} machine(s): {}".format(
                    observable, len(machines), "; ".join(results)
                )
            })


        # validate the observable type and service requested upon it
        # Note: "certificate thumbprint" is not supported by this responder
        #       since it would require a custom observable type for it.
        #
        if self.observable_type not in ACTIONS:
            self.error(
                "Observable type must be 'hostname', 'ip', 'url', 'domain', "
                "'fqdn', 'hash'"
            )
        elif self.service not in ACTIONS.get(self.observable_type, []):
            self.error(
                f"Action '{self.service}' not supported for type "
                f"'{self.observable_type}'.\n"
                f"Valid actions are {ACTIONS[self.observable_type]}"
            )

        # run action
        try:
            if self.service == "isolateMachine":
                isolate_machine(get_machine_id(self.observable))
            elif self.service == "unisolateMachine":
                unisolate_machine(get_machine_id(self.observable))
            elif self.service == "runFullVirusScan":
                run_full_virus_scan(get_machine_id(self.observable))
            elif self.service == "restrictAppExecution":
                restrict_app_execution(get_machine_id(self.observable))
            elif self.service == "unrestrictAppExecution":
                unrestrict_app_execution(get_machine_id(self.observable))
            elif self.service == "startAutoInvestigation":
                start_auto_investigation(get_machine_id(self.observable))
            elif self.service == "pushIOCBlock":
                push_custom_ioc(self.observable, 'Block', 'Low', False)
            elif self.service == "pushIOCAudit":
                push_custom_ioc(self.observable, 'Audit', 'Informational', True)
            elif self.service == "pushIOCAllowed":
                push_custom_ioc(self.observable, 'Allowed', 'Informational', False)
            elif self.service == "pushIOCBlockAndRemediate":
                push_custom_ioc(self.observable, 'BlockAndRemediate', 'High', True)
            elif self.service == "pushIOCWarn":
                push_custom_ioc(self.observable, 'Warn', 'Medium', True)
            elif self.service == "stopAndQuarantineFile":
                stop_and_quarantine_file(self.observable)
            else:
                self.error("Unidentified service")
        except Exception as e:
            self.error(str(e))

    def operations(self, raw):
        tag = None
        if self.service == "isolateMachine":
            tag = "MSDefenderForEndpoint:isolated"
        elif self.service == "runFullVirusScan":
            tag = "MSDefenderForEndpoint:fullVirusScan"
        elif self.service == "unisolateMachine":
            tag = "MSDefenderForEndpoint:unIsolated"
        elif self.service == "restrictAppExecution":
            tag = "MSDefenderForEndpoint:restrictedAppExec"
        elif self.service == "unrestrictAppExecution":
            tag = "MSDefenderForEndpoint:unrestrictedAppExec"
        elif self.service == "pushIOCBlock":
            tag = "MSDefenderForEndpoint:pushIOCBlock"
        elif self.service == "pushIOCAudit":
            tag = "MSDefenderForEndpoint:pushIOCAudit"
        elif self.service == "pushIOCAllowed":
            tag = "MSDefenderForEndpoint:pushIOCAllowed"
        elif self.service == "pushIOCBlockAndRemediate":
            tag = "MSDefenderForEndpoint:pushIOCBlockAndRemediate"
        elif self.service == "pushIOCWarn":
            tag = "MSDefenderForEndpoint:pushIOCWarn"
        elif self.service == "stopAndQuarantineFile":
            tag = "MSDefenderForEndpoint:stopAndQuarantineFile"

        if tag:
            return [self.build_operation("AddTagToArtifact", tag=tag)]


if __name__ == '__main__':
  MSDefenderForEndpoint().run()
