#!/usr/bin/env python3
import json
import os
import re
import subprocess
import tempfile
from base64 import b64decode
from pathlib import Path

from cortexutils.responder import Responder


class MsDefenderOffice365Responder(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.service = self.get_param(
            'config.service', None, 'Service parameter is missing')
        self.certificate_base64 = self.get_param(
            'config.certificate_base64', None,
            'Config is missing certificate_base64')
        self.certificate_password = self.get_param(
            'config.certificate_password', None,
            'Config is missing certificate_password')
        self.app_id = self.get_param(
            'config.app_id', None,
            'Config is missing app_id')
        self.organization = self.get_param(
            'config.organization', None,
            'Config missing organization')
        self.block_expiration_days = self.get_param(
            'config.block_expiration_days', None,
            'Config missing block_expiration_days'
        )
        self.script_dir = os.path.join(Path(__file__).absolute(), 'scripts')

    def clean_output(self, stream: bytes):
        """Decode byte stream and remove ANSI color codes"""
        re_no_ansi = re.compile(r'\x1b[^m]*m')
        return re_no_ansi.sub('', stream.decode('utf-8'))

    def run(self):
        observable = self.get_data()
        o_data = observable['data']
        if isinstance(o_data, str) and '\n' in o_data:
            o_data = o_data.splitlines()
        if not isinstance(o_data, list):
            o_data = [o_data]

        if observable['dataType'] not in ['domain', 'fqdn', 'mail']:
            self.error(f"Data type {observable['dataType']} not supported.")

        try:
            clean_cert64 = re.sub(r'\s+', '', self.certificate_base64)
            cert_bytes = b64decode(clean_cert64)
            temp_cert_file = tempfile.NamedTemporaryFile(suffix='.pfx')
            temp_cert_file.write(cert_bytes)
            temp_cert_file.flush()
        except ValueError as e:
            self.error(f"While loading the certificate data: {e}")

        script_name = f'scripts/{self.service}_sender.ps1'
        process_args = [
            "pwsh",
            script_name,
            temp_cert_file.name,
            self.certificate_password,
            self.app_id,
            self.organization,
        ]
        if self.service == 'block':
            caseId = observable['case']['caseId']
            process_args.append(f"TheHive case #{caseId}")
            process_args.append(self.block_expiration_days),
        process_args += o_data

        try:
            result = subprocess.run(
                process_args,
                capture_output=True,
                timeout=60)
        except subprocess.TimeoutExpired:
            self.error(f"Timeout waiting for {script_name} to complete."
                       f"\nstdout: ${self.clean_output(result.stdout)}"
                       f"\nstderr: ${self.clean_output(result.stderr)}")

        scriptErr = self.clean_output(result.stderr)
        if len(scriptErr) > 0 or result.returncode != 0:
            self.error(
                "The powershell script reported an error: " + scriptErr +
                "\n\nThe script was called with using these parameters: " +
                process_args)

        try:
            # We should get back an array of dictionaries, one for each
            # endpoint that was submitted for action.
            scriptResult = json.load(self.clean_output(result.stdout))
            endpointResults = scriptResult['Value']
        except json.JSONDecodeError as e:
            self.error("Error while trying to parse powershell script"
                       f" as JSON: ${e}"
                       f"\n\nThe script output was: " +
                       self.clean_output(result.stdout))
        except ValueError:
            self.error("Failed to find the 'Value' key in the script output: "
                       + str(scriptResult))

        successful_endpoints = []
        errored_endpoints = []
        for endpoint in endpointResults:
            if 'Error' not in endpoint:
                self.error(
                    "Endpoint result is missing an 'Error' property: "
                    + str(endpoint))
            elif endpoint['Error'] is not None:
                errored_endpoints.append({
                    "action": endpoint['Action'],
                    "entry": endpoint['Value'],
                    "error": endpoint['Error'].get('Message',
                                                   str(endpoint['Error']))
                })
            else:
                successful_endpoints.append({
                    "action": endpoint['Action'],
                    "entry": endpoint['Value'],
                    "expiration": endpoint.get('ExpirationDate')
                })

        if len(errored_endpoints) > 0:
            report = {
                'message': "At least one endpoint action had an error.",
                'errored_endpoints': errored_endpoints,
                'successful_endpoints': successful_endpoints,
            }
            self.error(json.dumps(report))
        else:
            report = {
                'message': "All endpoint actions completed with no error",
                'successful_endpoints': successful_endpoints,
            }
            self.report(report)


if __name__ == '__main__':
    MsDefenderOffice365Responder().run()
