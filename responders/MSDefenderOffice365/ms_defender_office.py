#!/usr/bin/env python3
import os
import subprocess
import tempfile
from base64 import b64decode
from pathlib import Path
import re

from cortexutils.responder import Responder


class PaloAltoCortexXDRResponder(Responder):
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
        self.script_dir = os.path.join(Path(__file__).absolute(), 'scripts')

    def run(self):
        observable = self.get_data()
        o_data = observable['data']
        if not isinstance(o_data, list):
            o_data = [o_data]  # for consistency

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
            self.organization
        ]
        if self.service == 'block':
            caseId = observable['case']['caseId']
            process_args += f"TheHive case #{caseId}"
        process_args += o_data

        try:
            result = subprocess.run(
                process_args,
                capture_output=True,
                timeout=60)
        except subprocess.TimeoutExpired:
            self.error(f'Timeout waiting for {script_name} to complete.'
                       f'\nstdout: ${result.stdout}'
                       f'\nstderr: ${result.stderr}')

        if result.returncode != 0:
            err_msg = result.stderr.decode('utf-8')
            self.error(f'An error occurred: {err_msg}')

        self.report({
            'message': 'Operation completed successfully.',
            '_stdout': result.stdout,
            '_stderr': result.stderr,
        })


if __name__ == '__main__':
    PaloAltoCortexXDRResponder().run()
