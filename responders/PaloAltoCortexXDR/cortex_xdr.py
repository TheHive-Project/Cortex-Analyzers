#!/usr/bin/env python3
from datetime import datetime, timezone
import hashlib
import ipaddress
import secrets
import string
import time
from typing import Any, List, Literal, TypedDict
from pprint import pformat

import requests
from cortexutils.responder import Responder


class Endpoint(TypedDict):
    endpoint_id: str
    endpoint_name: str
    endpointTags: str
    endpoint_type: str
    endpoint_status: str
    os_type: str
    os_version: str
    ip: List[str]
    users: List[str]
    domain: str
    alias: str
    first_seen: int
    last_seen: int
    content_version: str


class GetEndpointSuccessReply(TypedDict):
    total_count: int
    result_count: int
    endpoints: List[Endpoint]


class GetEndpointErrorReply(TypedDict):
    err_code: int
    err_msg: str
    err_extra: Any


GetEndpointResponse = GetEndpointSuccessReply | GetEndpointErrorReply


class PaloAltoCortexXDRResponder(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.api_key = self.get_param(
            'config.api_key', None, 'Missing API key')
        self.api_key_id = self.get_param(
            'config.api_key_id', None, 'Missing API key ID')
        self.advanced_security = self.get_param(
            'config.advanced_security', None, 'Missing advanced_security')
        self.api_host = self.get_param(
            'config.api_host', None, 'Missing API host')
        self.isolate_polling_interval = self.get_param(
            'config.isolate_polling_interval', 30)
        self.isolate_max_polling_retries = self.get_param(
            'config.isolate_max_polling_retries', 60)
        self.scan_polling_interval = self.get_param(
            'config.scan_polling_interval', 30)
        self.scan_max_polling_retries = self.get_param(
            'config.scan_max_polling_retries', 30)
        self.allow_multi_target = self.get_param(
            'config.allow_multiple_isolation_targets', False)
        self.service = self.get_param(
            'config.service', None, 'Missing config.service')
        if self.api_host.startswith('http'):
            self.error('api_host should be a FQDN, not a URL')
        self.api_root = f'https://{self.api_host}/public_api/v1'

        self.current_endpoints = []
        self.session = requests.Session()
        self.session.verify = True
        self.session.proxies = self.get_param('config.proxy', None)

    def _check_for_api_errors(self, response: requests.Response,
                              error_prefix="", good_status_code=200):
        """Check for API a failure response and exit with error if needed"""
        if response.status_code != good_status_code:
            try:
                response_json = response.json()
            except requests.JSONDecodeError:
                self.error('Failed to JSON decode response: ' + str(response))

            if 'reply' not in response_json:
                self.error(
                    'Response is missing the expected "reply" key: ' +
                    pformat(response_json)
                )

            reply = response_json['reply']
            message = error_prefix + "Error {err_code}: {err_msg}".format(
                **reply)
            if (err_extra := reply.get('err_extra')) is not None:
                message += f". {err_extra}"
            message += (f'\nWe expected status code {good_status_code} but'
                        f' got {response.status_code} with the error message'
                        ' reported above.')

            self.error(str({
                'message': message,
                'request_body': str(response.request.body),
                'endpoints': self.current_endpoints
            }))

    def _make_api_request(self, method: str, error_prefix="", **kwargs):
        headers = self._get_auth_header()
        response = self.session.request(method, headers=headers, **kwargs)
        self._check_for_api_errors(response, error_prefix)
        response_json = response.json()

        if 'reply' not in response_json:
            self.error("Missing reply in response. Did the API change?"
                       f" {response_json=}")
        return response_json

    def _get_auth_header(self):
        """Build headers appropriate for the type of API key we have"""
        if self.advanced_security:
            # Generate a 64 bytes random string
            nonce = "".join([secrets.choice(string.ascii_letters +
                                            string.digits) for _ in range(64)])
            # Get the current timestamp as milliseconds.
            timestamp = int(datetime.now(
                timezone.utc).timestamp()) * 1000
            # Generate the auth key:
            auth_key = "%s%s%s" % (self.api_key, nonce, timestamp)
            # Convert to bytes object
            auth_key = auth_key.encode("utf-8")
            # Calculate sha256:
            api_key_hash = hashlib.sha256(auth_key).hexdigest()
            # Generate HTTP call headers
            return {
                "x-xdr-timestamp": str(timestamp),
                "x-xdr-nonce": nonce,
                "x-xdr-auth-id": str(self.api_key_id),
                "Authorization": api_key_hash,
            }
        else:
            return {
                'x-xdr-auth-id': self.api_key_id,
                'Authorization': self.api_key,
                'Content-Type': 'application/json'
            }

    def get_endpoints(
            self,
            filter_field: Literal['ip_list', 'hostname'],
            data: List[str]
    ) -> GetEndpointResponse:
        """Find endpoint(s) using either a hostname or ip_list filter

        Args:
            filter_field: The field being used to search for endpoint(s)
            data: The data to match on an endpoint's filter_field

        Returns:
            Endpoints
        """
        url = f"{self.api_root}/endpoints/get_endpoint/"
        response_json = self._make_api_request(
            'post',
            'get_endpoints:',
            url=url,
            json={
                'request_data': {
                    'filters': [
                        {
                            'field': filter_field,
                            'operator': 'in',
                            'value': data
                        }
                    ]
                }
            }
        )
        self.current_endpoints = response_json.get(
            'reply', {}).get('endpoints')
        return response_json['reply']

    def scan_endpoints(self, endpoints: List[Endpoint]):
        """Run a scan on selected endpoints."""
        url = f'{self.api_root}/endpoints/scan/'
        endpoint_log = []

        scannable_endpoints = []
        unscannable_endpoints = []
        for e in endpoints:
            if e['scan_status'] not in [
                    'PENDING', 'IN_PROGRESS', 'SCAN_STATUS_IN_PROGRESS']:
                scannable_endpoints.append(e)
                endpoint_log.append(
                    'Found scannable endpoint: ' + e['endpoint_id'])
            else:
                unscannable_endpoints.append(e)
                endpoint_log.append(
                    'Found endpoint with scan already in progress: ' +
                    e['endpoint_id'])

        endpoint_ids = [e['endpoint_id'] for e in scannable_endpoints]

        endpoints_terse = []
        for e in endpoints:
            endpoints_terse.append(
                f"Name: {e['endpoint_name']} | ID: {e['endpoint_id']}")

        if len(endpoint_ids) == 0:
            return self.report({
                'success': True,
                'message': (
                    'No endpoints to scan or scans are already pending.'),
                'endpoints': endpoints_terse
            })

        response_json = self._make_api_request(
            'post',
            'scan_endpoint:',
            url=url,
            json={
                'request_data': {
                    'filters': [
                        {
                            'field': 'endpoint_id_list',
                            'operator': 'in',
                            'value': endpoint_ids
                        }
                    ]
                }
            }
        )
        action_id = response_json['reply']['action_id']
        action_result = self.poll_action_status(action_id, 'scan')
        if not action_result['success']:
            self.error(str(action_result))

        self.report({
            'success': True,
            'message': 'Finished endpoint scan.',
            'action_status': action_result['action_status'],
            'endpoints': endpoints_terse
        })

    def get_action_status(self, action_id):
        """Check the status of an action"""
        url = f'{self.api_root}/actions/get_action_status/'
        response_json = self._make_api_request('post', url=url, json={
            'request_data': {
                'group_action_id': action_id
            }
        })
        return response_json['reply']['data']

    def poll_action_status(self, action_id, action_type):
        """Check status of an action until it is finished"""
        action_status = {}
        # Since scans can take hours, if we see that the scan is in progress
        # or pending then we'll return success.
        terminal_statuses = [
            'CANCELLED', 'ABORTED', 'EXPIRED', 'COMPLETED_SUCCESSFULLY',
            'FAILED', 'TIMEOUT', 'SCAN_STATUS_IN_PROGRESS', 'IN_PROGRESS',
            'PENDING']

        if action_type in ['isolate', 'unisolate']:
            interval = self.isolate_polling_interval
            max_tries = self.isolate_max_polling_retries
        else:
            interval = self.scan_polling_interval
            max_tries = self.scan_max_polling_retries

        tries = 0
        while (not action_status
               or (tries < max_tries
                   and not all([status in terminal_statuses
                                for status in action_status.values()]))
               ):
            time.sleep(interval)
            action_status = self.get_action_status(action_id)
            tries += 1

        # Action status should be a mapping from endpoint IDs to status string,
        # so check if any of the statuses has not reached a terminal state
        if not all([x in terminal_statuses for x in action_status.values()]):
            message = (
                f'Timed out waiting to get status on scan action {action_id}.'
                f' Last status was: {action_status}.'
            )
            return {
                'success': False,
                'message': message,
                'action_status': action_status
            }
        else:
            return {'success': True, 'action_status': action_status}

    def isolate_endpoints(self, endpoints: List[Endpoint]):
        """Isolate one or more endpoints"""
        url = f'{self.api_root}/endpoints/isolate/'
        endpoint_ids = [e['endpoint_id'] for e in endpoints]
        endpoints_terse = []
        for e in endpoints:
            endpoints_terse.append(
                f"Name: {e['endpoint_name']} | ID: {e['endpoint_id']}")

        response_json = self._make_api_request(
            'post',
            url=url,
            json={
                'request_data': {
                    'filters': [
                        {
                            'field': 'endpoint_id_list',
                            'operator': 'in',
                            'value': endpoint_ids
                        }
                    ]
                }
            }
        )
        action_id = response_json['reply']['action_id']
        action_result = self.poll_action_status(action_id, 'isolate')
        if not action_result['success']:
            self.error(str(action_result))
        self.report({
            'message': (
                'Finished isolate action without errors on endpoints: ' +
                str(endpoints_terse)),
            'action_status': action_result['action_status'],
        })

    def unisolate_endpoints(self, endpoints: List[Endpoint]):
        """Unisolate one or more endpoints"""
        url = f'{self.api_root}/endpoints/unisolate/'
        endpoint_ids = [e['endpoint_id'] for e in endpoints]
        endpoints_terse = []
        for e in endpoints:
            endpoints_terse.append(
                f"Name: {e['endpoint_name']} | ID: {e['endpoint_id']}")

        response_json = self._make_api_request(
            'post',
            url=url,
            json={
                'request_data': {
                    'filters': [
                        {
                            'field': 'endpoint_id_list',
                            'operator': 'in',
                            'value': endpoint_ids
                        }
                    ]
                }
            }
        )
        action_id = response_json['reply']['action_id']
        action_result = self.poll_action_status(action_id, 'unisolate')
        if not action_result['success']:
            self.error(str(action_result))
        self.report({
            'message': (
                'Finished unisolate action without errors on endpoints: ' +
                str(endpoints_terse)),
            'action_status': action_result['action_status'],
        })

    def run(self):
        observable = self.get_data()

        if observable['dataType'] not in ['fqdn', 'ip']:
            self.error("Only 'fqdn' and 'ip' observables are supported.")

        o_data = observable['data']
        if isinstance(o_data, str) and '\n' in o_data:
            o_data = o_data.splitlines()
        if not isinstance(o_data, list):
            o_data = [o_data]

        # Make sure there are no empty/whitespace strings in the list
        o_data = list(filter(None, map(str.strip, o_data)))

        if (self.service != 'scan'
                and len(o_data) > 1
                and not self.allow_multi_target):
            self.error(
                f'{self.service} requested on multiple targets but'
                ' this has been disallowed in the responder configuration.')

        if observable['dataType'] == 'ip':
            filter_field = 'ip_list'
            try:
                for ip in o_data:
                    ipaddress.ip_address(ip)
            except ValueError as e:
                self.error(str(e))
        else:
            filter_field = 'hostname'

        actionable_endpoints = []
        no_action_needed_endpoints = []
        endpoints_response = self.get_endpoints(filter_field, o_data)
        endpoints = endpoints_response['endpoints']

        if self.service in ['isolate', 'unisolate']:
            if len(endpoints) == 0:
                self.error('Could not find any endpoints searching'
                           f' {filter_field} for {o_data}')

            if self.service == 'isolate':
                desired_state = 'AGENT_ISOLATED'
            else:
                desired_state = 'AGENT_UNISOLATED'

            for endpoint in endpoints:
                if endpoint['is_isolated'] == desired_state:
                    no_action_needed_endpoints.append(endpoint)
                else:
                    actionable_endpoints.append(endpoint)

        if (self.service in ['isolate', 'unisolate']
                and len(actionable_endpoints) == 0):
            self.report({
                'success': True,
                'message': ('No action taken because endpoints are already'
                            ' in the desired state'),
                'endpoints': self.current_endpoints
            })
        elif self.service == 'isolate':
            self.isolate_endpoints(actionable_endpoints)
        elif self.service == 'unisolate':
            self.unisolate_endpoints(actionable_endpoints)
        elif self.service == 'scan':
            self.scan_endpoints(endpoints)
        else:
            self.error(f'Service {self.service} is not implemented')


if __name__ == '__main__':
    PaloAltoCortexXDRResponder().run()
