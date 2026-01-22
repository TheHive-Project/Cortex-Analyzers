#!/usr/bin/env python3
import json
import os
import re
import subprocess
import tempfile
from base64 import b64decode
import ipaddress

from cortexutils.responder import Responder

try:
    """
    python v3.13
    """
    from ipaddress import ipv6_mapped as ipv6_mapped
except ImportError:
    def ipv6_mapped(self):
        """Return the IPv4-mapped IPv6 address.
        Returns:
            The IPv4-mapped IPv6 address per RFC 4291.
        """
        return ipaddress.IPv6Address(f'::ffff:{self}')


def ipv4_to_ipv6(ipv4):
    """
        Return the IPv6 mapped address of ipv4
    """
    if ipv4 and ":" in ipv4:
        return ipv4
    if "/" in ipv4:
        ipv4_net = ipaddress.IPv4Network(ipv4, strict=False)
        ipv4_int = int(ipv4_net.network_address)
        ipv6_int = (0x00000000000000000000FFFF << 32) | ipv4_int  # ::ffff:0:0 + IPv4
        ipv6_prefixlen = 96 + ipv4_net.prefixlen  # mapped IPv6 prefix
        return str(ipaddress.IPv6Network((ipv6_int, ipv6_prefixlen), strict=False))
    else:
        return ipv6_mapped(ipaddress.IPv4Address(ipv4)).compressed


def ipv6_to_ipv4(ipv6: str):
    """
        If ipv6 is an IPv4-mapped IPv6 address, return the IPv4 string.
        Otherwise return the IPv6 address.
    """
    if "." in ipv6:
        return ipv6
    try:
        ipv4 = ipaddress.ip_address(ipv6)
        # Only IPv6 objects have .ipv4_mapped; for others, return None
        if isinstance(ipv4, ipaddress.IPv6Address) and ipv4.ipv4_mapped:
            return str(ipv4.ipv4_mapped)
    except:
        try:
            if "/" in ipv6:
                ipv6_net = ipaddress.ip_network(ipv6, False)
                ipv4_prefixlen = ipv6_net.prefixlen  - 96 # mapped IPv4 prefix
                ipv6 = ipv6_net.network_address.ipv4_mapped.compressed
                return f'{ipv6}/{ipv4_prefixlen}'
        except:
            pass
    return str(ipv6)


ACTIONS = {
    'ip': ['allow', 'block', 'disallow', 'unblock'],
    'url': ['allow', 'block', 'disallow', 'unblock'],
    'domain': ['block', 'disallow', 'unblock'],
    'fqdn': ['block', 'disallow', 'unblock'],
    'mail': ['block', 'disallow', 'unblock'],
    'hash': ['block', 'disallow', 'unblock'],
    'sha256': ['block', 'disallow', 'unblock'],
}


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
        self.script_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'scripts')

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

        o_data_orig = o_data.copy()
        observableType = observable['dataType']

        # validate the observable type and service requested upon it
        # Note: "sha256" is a custom observable type
        if observableType not in ACTIONS:
            self.error({'message': "Observable type must be 'hostname', 'ip', 'url', 'domain', 'fqdn', 'hash', 'sha256'"})
        elif self.service not in ACTIONS.get(observableType, []):
            self.error(
              {'message': f"Action '{self.service}' not supported for type '{observableType}'.\n"
                          f"Valid actions are {ACTIONS[observableType]}" })

        if observableType == 'ip':
            o_data_fix = []
            for o in o_data:
                try:
                    o = ipv4_to_ipv6(o)
                except:
                    self.report({'message':"Observable is not a valid ip: %s, skipping" % o })
                o_data_fix.append(o)
            if len(o_data_fix) == 0:
                self.error("Observable is not a valid IP nor CIDR")
            o_data = o_data_fix.copy()
            listType = 'IP'
        elif observableType == 'url':
            listType = 'Url'
        elif observableType in ('domain', 'fqdn', 'mail'):
            listType = 'Sender'
        elif observableType in ('hash', 'sha256'):
            o_data_fix = []
            for o in o_data:
                if not len(o) == 64:
                    self.report({'message':"Observable is not a valid hash: %s, skipping" % o })
                else:
                    o_data_fix.append(o)
            if len(o_data_fix) == 0:
                self.error("Observable is not a valid hash")
            o_data = o_data_fix.copy()
            listType = 'FileHash'

        try:
            clean_cert64 = re.sub(r'\s+', '', self.certificate_base64)
            cert_bytes = b64decode(clean_cert64)
            temp_cert_file = tempfile.NamedTemporaryFile(suffix='.pfx')
            temp_cert_file.write(cert_bytes)
            temp_cert_file.flush()
        except ValueError as e:
            self.error(f"While loading the certificate data: {e}")

        script_name = f'{self.script_dir}/{self.service}.ps1'
        process_args = [
            "pwsh",
            script_name,
            temp_cert_file.name,
            self.certificate_password,
            self.app_id,
            self.organization,
            listType,
        ]
        if self.service in ('block', 'allow'):
            caseId = observable['case']['caseId']
            process_args.append(f"TheHive case #{caseId} - {','.join(o_data_orig)}")
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

        successful_entries = []
        error_entries = []
        if scriptErr:
            for o in o_data:
                if f'{o} - Duplicate value' in scriptErr:
                    successful_entries.append(
                        f'{o}: "Entry already {self.service}ed"'
                    )
                elif 'Entry not found.' in scriptErr:
                    successful_entries.append(
                        f'{o}: "Entry already {self.service}ed"'
                    )
                else:
                    error_entries.append(
                        f'{o}: "Invalid value or action\n{scriptErr}"'
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

        for item in scriptResultDict:
            result_msg = item
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
            elif item.get('stdout') and 'Invalid value to add' in item.get('stdout'):
                error_entries.append(
                        f"{item['entry']}: {item['stdiout']}"
                    )
            elif item.get('result'):
                success_dict = json.loads(item['result'])
                if self.service in ('block', 'allow'):
                    result_msg = (f"{item['entry']} Expiration " +
                                  str(success_dict['ExpirationDate']))
                else:
                    result_msg = item['entry']
            if result_msg:
                successful_entries.append(result_msg)

        # error & exit
        if len(error_entries) > 0:
            self.error(json.dumps({
                'message': "At least one endpoint action had an error.",
                'errored_entries': error_entries,
                'successful_entries': successful_entries,
            }))

        # report
        if len(successful_entries) == 0:
            report = {
                'message': "No change to entries",
            }
        else:
            report = {
                'message': "All endpoint actions completed with no error",
                'entries': successful_entries,
            }
        self.report(report)

    def operations(self, raw):
        #self.build_operation('AddTagToCase', tag='MSDefenderO365Responder:run')
        if self.service == "block":
            return [self.build_operation("AddTagToArtifact", tag="MsDefenderO365:block")]
        elif self.service == "unblock":
            return [self.build_operation("AddTagToArtifact", tag="MsDefenderO365:unblock")]
        elif self.service == "allow":
            return [self.build_operation("AddTagToArtifact", tag="MsDefenderO365:allow")]
        elif self.service == "disallow":
            return [self.build_operation("AddTagToArtifact", tag="MsDefenderO365:disallow")]

    def summary(self, raw):
        taxonomies = []
        namespace = "MsDefenderO365"
        predicate = "TenantAllowBlockList"

        value = f"{self.service}"
        if self.service in ("block", "disallow"):
            level = "suspicious"
        else:
            level = "safe"

        taxonomies.append({"level": level, "namespace": namespace, "predicate": predicate, "value": value})
        return {"taxonomies": taxonomies}

if __name__ == '__main__':
    MsDefenderOffice365Responder().run()
