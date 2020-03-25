#!/usr/bin/env python3
import io
import json
import requests
import ipaddress

from cortexutils.analyzer import Analyzer
from cortexutils.extractor import Extractor
from glob import glob
from os.path import exists


class MISPWarninglistsAnalyzer(Analyzer):
    """
    This analyzer compares given data to the MISP warning lists obtainable via
    https://github.com/MISP/misp-warninglists.
    Configuration options are:

    ```
    MISPWarningLists {
      path = "/path/to/misp-warninglists/repository"  # Default: "misp-warninglists"
    }
    ```
    """
    def __init__(self):
        Analyzer.__init__(self)

        self.data = self.get_data()
        self.path = self.get_param('config.path', 'misp-warninglists')
        if not exists(self.path):
            self.error('Path to misp-warninglists does not exist.')
        self.warninglists = self.readwarninglists()

    def readwarninglists(self):
        files = glob('{}/lists/*/*.json'.format(self.path))
        listcontent = []
        for file in files:
            with io.open(file, 'r') as fh:
                content = json.loads(fh.read())
                values = Extractor().check_iterable(content.get('list', []))
                obj = {
                    "name": content.get('name', 'Unknown'),
                    "values": [value['data'] for value in values],
                    "dataTypes": [value['dataType'] for value in values]
                }
                listcontent.append(obj)
        return listcontent

    def lastlocalcommit(self):
        try:
            with io.open('{}/.git/refs/heads/master'.format(self.path), 'r') as fh:
                return fh.read().strip('\n')
        except Exception as e:
            return 'Error: could not get local commit hash ({}).'.format(e)

    @staticmethod
    def lastremotecommit():
        url = 'https://api.github.com/repos/misp/misp-warninglists/branches/master'
        try:
            result_dict = requests.get(url).json()
            return result_dict['commit']['sha']
        except Exception as e:
            return 'Error: could not get remote commit hash ({}).'.format(e)

    def run(self):
        results = []
        data = self.data
        if self.data_type == 'ip':
            try:
                data = ipaddress.ip_address(self.data)
            except ValueError:
                return self.error("{} is said to be an IP address but it isn't".format(self.data))
        for list in self.warninglists:
            if self.data_type not in list.get('dataTypes'):
                continue

            if self.data_type == 'ip':
                for net in list.get('values', []):
                    try:
                        if data in ipaddress.ip_network(net):
                            results.append({"name": list.get('name')})
                            break
                    except ValueError:
                        # Ignoring if net is not a valid IP network since we want to compare ip addresses
                        pass
            else:
                if data.lower() in list.get('values', []):
                    results.append({
                        "name": list.get('name')
                    })

        self.report({
            "results": results,
            "is_uptodate": self.lastlocalcommit() == self.lastremotecommit()
        })

    def summary(self, raw):
        taxonomies = []
        if len(raw['results']) > 0:
            taxonomies.append(self.build_taxonomy('suspicious', 'MISP', 'Warninglists', 'Potential fp'))
        else:
            taxonomies.append(self.build_taxonomy('info', 'MISP', 'Warninglists', 'No hits'))

        if not raw.get('is_uptodate', False):
            taxonomies.append(self.build_taxonomy('info', 'MISP', 'Warninglists', 'Outdated'))

        return {
            "taxonomies": taxonomies
        }


if __name__ == '__main__':
    MISPWarninglistsAnalyzer().run()
