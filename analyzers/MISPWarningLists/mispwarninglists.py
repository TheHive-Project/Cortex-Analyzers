#!/usr/bin/env python
import io
import json

from cortexutils.analyzer import Analyzer
from glob import glob
from os.path import exists


class MISPWarninglistsAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.data = self.get_data()
        self.path = self.get_param('config.path', 'misp-warninglists')
        if not exists(self.path):
            self.error('Path to misp-warninglists does not exist.')
        self.warninglists = self.__readwarninglists()

    def __readwarninglists(self):
        files = glob('{}/lists/*/*.json'.format(self.path))
        listcontent = []
        for file in files:
            with io.open(file, 'r') as fh:
                content = json.loads(fh.read())
                obj = {
                    "name": content.get('name', 'Unknown'),
                    "values": content.get('list', []),
                    "dataTypes": []
                }
                for type in content.get('matching_attributes', []):
                    if type in ['md5', 'sha1', 'sha256', 'ssdeep']:
                        obj['dataTypes'].append('hash')
                        continue
                    if 'filename|' in type:
                        obj['dataTypes'].append('hash')
                        continue
                    if 'ip' in type:
                        obj['dataTypes'].append('ip')
                        continue
                    if 'domain' in type:
                        obj['dataTypes'].append('domain')
                        continue
                    if 'url' in type:
                        obj['dataTypes'].append('url')
                listcontent.append(obj)
        return listcontent

    def __lastcommit(self):
        with io.open('{}/.git/refs/head/master'.format(self.path), 'r') as fh:
            return fh.read()

    def run(self):
        results = []
        for list in self.warninglists:
            if self.data_type not in list.get('dataTypes'):
                continue

            if self.data in list.get('values', []):
                results.append({
                    'name': list.get('name')
                })

        self.report({
            "results": results,
            "last_update": self.__lastcommit()}
        )

    def summary(self, raw):
        taxonomies = []
        if len(raw['results']) > 0:
            taxonomies.append(self.build_taxonomy('suspicious', 'MISP', 'Warninglists', 'Potential fp'))
        else:
            taxonomies.append(self.build_taxonomy('info', 'MISP', 'Warninglists', 'No hits'))

        return {
            "taxonomies": taxonomies
        }


if __name__ == '__main__':
    MISPWarninglistsAnalyzer().run()
