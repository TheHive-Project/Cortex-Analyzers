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
        self.quarantine_file_hash = self.get_param('config.file_hash', None)
        self.quarantine_file_path = self.get_param('config.file_path', None)
        self.forensics_collector_uuid = self.get_param(
            'config.collector_uuid', None)
        self.hash_comment = self.get_param('config.comment', None)
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

    def cancel_scan_endpoints(self, endpoints: List[Endpoint]):
        """Cancel a running scan on selected endpoints."""
        url = f'{self.api_root}/endpoints/abort_scan'
        endpoint_ids = [e['endpoint_id'] for e in endpoints]
        endpoints_terse = [
            f"Name: {e['endpoint_name']} | ID: {e['endpoint_id']}"
            for e in endpoints
        ]

        response_json = self._make_api_request(
            'post',
            'cancel_scan:',
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
        action_result = self.poll_action_status(action_id, 'cancel_scan')
        if not action_result['success']:
            self.error(str(action_result))

        self.report({
            'success': True,
            'message': 'Finished cancel scan action.',
            'action_status': action_result['action_status'],
            'endpoints': endpoints_terse
        })

    def _make_boolean_api_request(self, url: str, error_prefix: str, body: dict):
        """Make an API request whose success response is a raw boolean (not a reply object)."""
        headers = self._get_auth_header()
        response = self.session.request('post', url=url, headers=headers,
                                        json=body)
        if response.status_code != 200:
            self.error(f'{error_prefix} request failed with status'
                       f' {response.status_code}: {response.text}')
        result = response.json()
        if result is not True:
            self.error(f'{error_prefix} unexpected response: {result}')

    def block_list_hashes(self, hash_list: List[str]):
        """Add file hashes to the block list."""
        url = f'{self.api_root}/hash_exceptions/blocklist'
        request_data = {'hash_list': hash_list}
        if self.hash_comment:
            request_data['comment'] = self.hash_comment
        self._make_boolean_api_request(
            url, 'block_list:',
            {'request_data': request_data}
        )
        self.report({
            'success': True,
            'message': (
                f'Successfully added {len(hash_list)} hash(es) to the'
                ' block list.'),
            'hashes': hash_list
        })

    def initiate_forensics_triage(self, endpoints: List[Endpoint]):
        """Initiate forensics triage collection on selected endpoints.

        Requires Forensics add-on license. Agents must have Forensics
        License enabled and must all be the same OS (Windows or macOS).
        Maximum 10 concurrent triage actions.
        """
        url = f'{self.api_root}/triage_endpoint'
        agent_ids = [e['endpoint_id'] for e in endpoints]

        request_data = {'agent_ids': agent_ids}
        if self.forensics_collector_uuid:
            request_data['collector_uuid'] = self.forensics_collector_uuid

        response_json = self._make_api_request(
            'post',
            'initiate_forensics:',
            url=url,
            json={'request_data': request_data}
        )
        reply = response_json['reply']
        self.report({
            'success': True,
            'message': 'Forensics triage initiated.',
            'group_action_id': reply.get('group_action_id'),
            'successful_agent_ids': reply.get('successful_agent_ids', []),
            'unsuccessful_agent_ids': reply.get('unsuccessful_agent_ids', [])
        })

    def allow_list_hashes(self, hash_list: List[str]):
        """Add file hashes to the allow list."""
        url = f'{self.api_root}/hash_exceptions/allowlist'
        request_data = {'hash_list': hash_list}
        if self.hash_comment:
            request_data['comment'] = self.hash_comment
        self._make_boolean_api_request(
            url, 'allow_list:',
            {'request_data': request_data}
        )
        self.report({
            'success': True,
            'message': (
                f'Successfully added {len(hash_list)} hash(es) to the'
                ' allow list.'),
            'hashes': hash_list
        })

    def restore_file(self, file_hash: str):
        """Restore a quarantined file on all endpoints where it was quarantined."""
        url = f'{self.api_root}/endpoints/restore'
        response_json = self._make_api_request(
            'post',
            'restore_file:',
            url=url,
            json={
                'request_data': {
                    'file_hash': file_hash
                }
            }
        )
        reply = response_json['reply']
        action_id = reply['action_id']
        action_result = self.poll_action_status(action_id, 'restore_file')
        if not action_result['success']:
            self.error(str(action_result))
        self.report({
            'success': True,
            'message': 'File restore action completed.',
            'action_status': action_result['action_status'],
            'endpoints_count': reply.get('endpoints_count'),
            'file_hash': file_hash
        })

    def quarantine_file(self, endpoints: List[Endpoint],
                        file_hash: str, file_path: str = None):
        """Quarantine a file by hash on selected endpoints."""
        url = f'{self.api_root}/endpoints/quarantine'
        endpoint_ids = [e['endpoint_id'] for e in endpoints]
        endpoints_terse = [
            f"Name: {e['endpoint_name']} | ID: {e['endpoint_id']}"
            for e in endpoints
        ]

        request_data = {
            'filters': [
                {
                    'field': 'endpoint_id_list',
                    'operator': 'in',
                    'value': endpoint_ids
                }
            ],
            'file_hash': file_hash
        }
        if file_path:
            request_data['file_path'] = file_path

        response_json = self._make_api_request(
            'post',
            'quarantine:',
            url=url,
            json={'request_data': request_data}
        )
        action_id = response_json['reply']['action_id']
        action_result = self.poll_action_status(action_id, 'quarantine')
        if not action_result['success']:
            self.error(str(action_result))
        self.report({
            'success': True,
            'message': 'File quarantine action completed.',
            'action_status': action_result['action_status'],
            'endpoints': endpoints_terse,
            'file_hash': file_hash
        })

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

        # Hash-only services — no endpoint lookup needed
        if self.service in ['block_list', 'allow_list', 'restore_file']:
            if observable['dataType'] != 'hash':
                self.error(f"Only 'hash' observables are supported for"
                           f" {self.service}.")
            o_data = observable['data']
            if isinstance(o_data, str) and '\n' in o_data:
                o_data = o_data.splitlines()
            if not isinstance(o_data, list):
                o_data = [o_data]
            o_data = list(filter(None, map(str.strip, o_data)))
            if self.service == 'block_list':
                self.block_list_hashes(o_data)
            elif self.service == 'allow_list':
                self.allow_list_hashes(o_data)
            elif self.service == 'restore_file':
                if len(o_data) != 1:
                    self.error('restore_file supports exactly one hash'
                               ' observable.')
                self.restore_file(o_data[0])
            return

        # All other services work on endpoints (ip/fqdn)
        if observable['dataType'] not in ['fqdn', 'ip']:
            self.error("Only 'fqdn' and 'ip' observables are supported.")

        o_data = observable['data']
        if isinstance(o_data, str) and '\n' in o_data:
            o_data = o_data.splitlines()
        if not isinstance(o_data, list):
            o_data = [o_data]

        # Make sure there are no empty/whitespace strings in the list
        o_data = list(filter(None, map(str.strip, o_data)))

        if (self.service in ['isolate', 'unisolate']
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
        elif self.service == 'cancel_scan':
            self.cancel_scan_endpoints(endpoints)
        elif self.service == 'initiate_forensics':
            self.initiate_forensics_triage(endpoints)
        elif self.service == 'quarantine':
            if not self.quarantine_file_hash:
                self.error(
                    'config.file_hash is required for the quarantine service.')
            self.quarantine_file(
                endpoints, self.quarantine_file_hash,
                self.quarantine_file_path)
        else:
            self.error(f'Service {self.service} is not implemented')


if __name__ == '__main__':
    PaloAltoCortexXDRResponder().run()
