#!/usr/bin/env python3
# encoding: utf-8

import time
import socket
import json

from cortexutils.analyzer import Analyzer
from nessrest import ness6rest
from netaddr import IPNetwork, IPAddress


class NessusAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.url = self.get_param(
            'config.url', None, 'Missing Nessus scanner URL')
        self.login = self.get_param(
            'config.login', None, 'Missing Nessus scanner login')
        self.password = self.get_param(
            'config.password', None, 'Missing Nessus scanner password')
        self.policy = self.get_param(
            'config.policy', None, 'Missing Nessus scanner policy')
        self.ca_bundle = self.get_param(
            'config.ca_bundle')
        self.allowed_networks = self.get_param(
            'config.allowed_networks')

    def summary(self, raw):
        summary = {}
        if "vulnerabilities" in raw:
            count = [0, 0, 0, 0, 0]
            for vuln in raw["vulnerabilities"]:
                count[vuln["severity"]] += 1
            summary["info"]     = count[0]
            summary["low"]      = count[1]
            summary["medium"]   = count[2]
            summary["high"]     = count[3]
            summary["critical"] = count[4]

        taxonomies = []
        level = "info"
        namespace = "Nessus"
        predicate = "Info"

        if summary["info"] > 0:
            value = summary["info"]
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        if summary["low"] > 0:
            value = summary["low"]
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        if summary["medium"] > 0:
            value = summary["medium"]
            level = "suspicious"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        if summary["high"] > 0:
            value = summary["high"]
            level = "suspicious"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        if summary["critical"] > 0:
            value = summary["critical"]
            level = "malicious"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        data = self.get_param('data', None, 'Data is missing')

        if self.data_type != 'fqdn' and self.data_type != 'ip':
            self.error('Invalid data type')

        if self.allowed_networks is not None:
            if self.data_type == 'fqdn':
                address = IPAddress(socket.gethostbyname(data))
            else:
                try:
                    address = IPAddress(data)
                except Exception as e:
                    self.error("{}".format(e))
            if not any(address in IPNetwork(network) for network in self.allowed_networks):
                self.error('Invalid target: not in any allowed network')

        scanner_args = {
            'url': self.url,
            'login': self.login,
            'password': self.password
        }
        if self.ca_bundle is not None:
            scanner_args.update({'ca_bundle': self.ca_bundle})
        else:
            scanner_args.update({'insecure': True})

        try:
            scanner = ness6rest.Scanner(**scanner_args)
            scanner.policy_set(name=self.policy)
            scanner.scan_add(targets=data, name="cortex scan for " + data)

            self._run_scan(scanner)
            results = self._get_scan_results(scanner)
            self._delete_scan(scanner)
        except Exception as ex:
            self.error('Scanner error: %s' % ex)

        self.report(results)

    def _run_scan(self, scanner):
        scanner.action(
            action="scans/" + str(scanner.scan_id) + "/launch", method="POST")

        scan_uuid = scanner.res["scan_uuid"]

        running = True
        counter = 0

        while running:
            scanner.action(
                action="scans?folder_id=" + str(scanner.tag_id), method="GET")

            for scan in scanner.res["scans"]:
                if (scan["uuid"] == scan_uuid
                        and (scan['status'] == "running" or scan['status'] == "pending")):
                    time.sleep(2)
                    counter += 2

                if (scan["uuid"] == scan_uuid
                        and scan['status'] != "running" and scan['status'] != "pending"):
                    running = False

    def _get_scan_results(self, scanner):
        result = scanner.action(
            "scans/" + str(scanner.scan_id), method="GET", download=True)
        return json.loads(result)

    def _delete_scan(self, scanner):
        scanner.action(
            "scans/" + str(scanner.scan_id), method="DELETE")


if __name__ == '__main__':
    NessusAnalyzer().run()
