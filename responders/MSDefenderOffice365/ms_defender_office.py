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
            'config.block_expiration_days', 0)
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
            process_args.append(str(self.block_expiration_days))
        process_args += o_data

        try:
            result = subprocess.run(
                process_args,
                capture_output=True)
        except subprocess.TimeoutExpired:
            self.error(f"Timeout waiting for {script_name} to complete."
                       f"\nstdout: {self.clean_output(result.stdout)}"
                       f"\nstderr: {self.clean_output(result.stderr)}")

        scriptErr = self.clean_output(result.stderr)
        if result.returncode != 0:
            self.error(
                f"The powershell script reported an error: {scriptErr}"
                "\n\nThe non-error output was the following: " +
                self.clean_output(result.stdout)
            )

        try:
            # We should get back an array of dictionaries, one for each
            # endpoint that was submitted for action.
            scriptResult = self.clean_output(result.stdout)
            re_json_list = re.compile(r'\[\s*\{.*\}\s*\]', re.DOTALL)
            re_json_object = re.compile(r'\{.*\}', re.DOTALL)
            match_json_list = re_json_list.search(scriptResult)
            match_json_object = re_json_object.search(scriptResult)

            if match_json_list is not None:
                extractedJson = match_json_list.group()
                scriptResultDict = json.loads(extractedJson)
            elif match_json_object is not None:
                extractedJson = match_json_object.group()
                scriptResultDict = [json.loads(extractedJson)]
            else:
                self.error(
                    "Failed to identify JSON in script output:" +
                    scriptResult)
        except json.JSONDecodeError as e:
            self.error(f"Error decoding JSON: {e}"
                       f"| Input: {extractedJson}")

        successful_entries = []
        error_entries = []
        for item in scriptResultDict:
            if item.get('error') is not None:
                # Don't treat it as an error if the entry we're trying to
                # unblock already exists
                if 'Entry not found' in item['error']:
                    successful_entries.append(
                        f"{item['entry']}: Entry not found."
                    )
                else:
                    error_entries.append(
                        f"{item['entry']}: {item['error']}"
                    )
            else:
                success_dict = json.loads(item['result'])
                if self.service == 'block':
                    result_msg = (f"{item['entry']} Expiration " +
                                  str(success_dict['ExpirationDate']))
                else:
                    result_msg = item['entry']

                successful_entries.append(result_msg)

        if len(error_entries) > 0:
            report = {
                'message': "At least one endpoint action had an error.",
                'errored_entries': error_entries,
                'successful_entries': successful_entries,
            }
            self.error(json.dumps(report))
        else:
            report = {
                'message': "All endpoint actions completed with no error",
                'entries': successful_entries,
            }
            self.report(report)


if __name__ == '__main__':
    MsDefenderOffice365Responder().run()
