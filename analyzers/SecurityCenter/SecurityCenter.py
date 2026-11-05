#!/usr/bin/env python3
# encoding: utf-8

import re
import time
import socket

from cortexutils.analyzer import Analyzer
from tenable.sc import TenableSC 

class SCAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        base = 'config.'

        # using getParam(name, default=None, message=None)
        self.ip = self.get_param(
            base + 'host', None, 'Missing SecurityCenter IP')
        self.login = self.get_param(
            base + 'login', None, 'Missing SecurityCenter login')
        self.password = self.get_param(
            base + 'password', None, 'Missing SecurityCenter password')
        self.policyID = self.get_param(
            base + 'policy', None, 'Missing policy ID')
        self.credentialID = self.get_param(
            base + 'credential', None, 'Missing scan credential ID')
        self.reportID = self.get_param(
            base + 'report', None, 'Missing report ID')
        self.email_on_launch = self.get_param(
            base + 'emailOnLaunch', False, None)
        self.email_on_complete = self.get_param(
            base + 'emailOnComplete', False, None)

    def run(self):
        Analyzer.run(self)

        if self.data_type != 'ip' and self.data_type != 'fqdn': 
            self.error('Invalid data type')
            
        try:
            sc = TenableSC(self.ip)
            sc.login(self.login, self.password)
            
            results = self._run_scan(sc)

            sc.logout()
        
        except Exception as ex:
            self.error('Error: %s' % ex)

        self.report(results)

    def _run_scan(self, sc):
        target_hosts = re.split(r'[,\s]+', self.get_param('data'))
        name = 'CORTEX | '
        for i, h in enumerate(target_hosts):
            if (self.data_type == 'ip'):
                try:
                    hostname = socket.gethostbyaddr(h)[0].split('.')[0].upper()
                    # \u00A0 is &nbsp; (to make the report look nicer)
                    name += hostname + '\u00A0(' + h + ')'
                except Exception:
                    name += h
            elif (self.data_type == 'fqdn'):
                try:
                    hostname = h.split('.')[0].upper()
                    name += hostname + '\u00A0(' + socket.gethostbyname(h) + ')'
                except Exception:
                    name += h.split('0')[0].upper()
            if (i != len(target_hosts) - 1):
                name += ', '

        r = sc.scans.create(name            = name,
                            repo            = 1,
                            policy_id       = int(self.policyID),
                            email_launch    = self.email_on_launch,
                            email_complete  = self.email_on_complete,
                            credentials     = [{'id': self.credentialID}],
                            reports         = [{'id': self.reportID, 'reportSource': 'individual'}],
                            schedule        = {'type': 'now'},
                            targets         = target_hosts
                           )

        resultID = r['scanResultID']

        return self._get_scan_results(sc, resultID)
        
    def _get_scan_results(self, sc, resultID):
        results = {}
        while True:
            results = sc.scan_instances.details(int(resultID))  
            running = (results['running'].lower() == 'true')
            status = results['status'].lower()
            if (not running and status == 'completed'):
                break
            elif (status == 'error'):
                self.error("Error: " + results['errorDetails'])
            time.sleep(5)
        return results

if __name__ == '__main__':
    SCAnalyzer().run()
