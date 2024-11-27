#!/usr/bin/env python3

import csv
import glob
import os.path
import ipaddress
from cortexutils.analyzer import Analyzer


def rows_of_csvs(csv_dir):
    for csvfn in glob.glob(os.path.join(csv_dir, '*.csv')):
        with open(csvfn, 'rt') as csvf:
            first_line = next(csvf)
            if not first_line.startswith('#TYPE'):
                # oops, let's not skip that. start over
                csvf.seek(0)
            # at this point, type info or no, we should be on the line
            # with the headers
            d = csv.DictReader(csvf)
            for i, row in enumerate(d, start=1):
                row['_File'] = csvfn
                row['_Row'] = i
                yield row


def subnets(rows):
    for d in rows:
        # by using these titles here, we are assuming they are written
        # at the top of columns in the CSV files we parsed
        yield {
            'net': ipaddress.ip_network(d['ScopeId'] + '/' + d['SubnetMask']),
            'first_ip': ipaddress.ip_address(d['StartRange']),
            'last_ip': ipaddress.ip_address(d['EndRange']),
            'name': d['Name'],
        }


def get_name_of_subnet(scopes, ip_str):
    a = ipaddress.ip_address(ip_str)
    for scope in scopes:
        if a in scope['net']:
            if (a >= scope['first_ip']) and (a <= scope['last_ip']):
                return scope['name']
    raise KeyError(ip_str)


class DHCPInfoAnalyzer(Analyzer):
    def __init__(self):
        super().__init__()
        self.dhcp_info_directory = self.get_param(
            'config.dhcp_info_directory', None,
            'DHCP Info directory is missing')

    def summary(self, raw):
        taxonomies = []
        if 'dhcp_scope_name' in raw:
            taxonomies.append(self.build_taxonomy(
                'info', 'DHCP', 'ScopeName', raw['dhcp_scope_name']))
        return {'taxonomies': taxonomies}

    def run(self):
        super().run()
        if self.data_type == 'ip':
            all_rows = rows_of_csvs(self.dhcp_info_directory)
            scopes = list(subnets(all_rows))
            try:
                data = self.get_data()
                subnet_name = get_name_of_subnet(scopes, data)
                self.report({
                    'dhcp_scope_name': subnet_name,
                })
            except KeyError:
                self.report({
                    'not_found': ('address {} not found '
                                  'in any of the {} known '
                                  'DHCP scopes'.format(data, len(scopes))),
                })
            except Exception as e:
                self.unexpectedError(repr(e))
        else:
            self.notSupported()


if __name__ == '__main__':
    DHCPInfoAnalyzer().run()
