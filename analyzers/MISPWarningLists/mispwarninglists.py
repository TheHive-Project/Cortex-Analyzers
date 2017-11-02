#!/usr/bin/env python
import io
import json
import pygit2

from cortexutils.analyzer import Analyzer
from glob import glob
from time import sleep, time
from shutil import rmtree
from os.path import exists
from os import remove


class MISPWarninglistsAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        # Wait for unlocking the repo
        while exists('.lock'):
            sleep(5)

        self.delta = None

        if self.get_param('config.enablepull', True) and self.__needpull():
            self.__pullrepo()

        self.data = self.getData()
        self.warninglists = self.__readwarninglists()

    def __needpull(self):
        if not exists('last_update.json'):
            return True
        with io.open('last_update.json', 'r') as fh:
            self.delta = abs(float(json.loads(fh.read()).get('last_update', 0)) - time())
        if self.delta > self.get_param('config.alloweddelta', 86400):
            return True
        return False

    def __pullrepo(self):
        # Todo: Implement git pulling instead of cloning, if repo is already cloned

        # lock
        with io.open('.lock', 'w') as fh:
            fh.write(str(time()))

        # update
        if exists('misp-warninglists'):
            rmtree('misp-warninglists')

        pygit2.clone_repository('https://github.com/MISP/misp-warninglists', 'misp-warninglists')
        with io.open('last_update.json', 'w') as fh:
            fh.write(json.dumps({'last_update': time()}))
        self.delta = 0

        # rm lock
        remove('.lock')

    def __readwarninglists(self):
        files = glob('misp-warninglists/lists/*/*.json')
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
                    if 'url' in type:
                        obj['dataTypes'].append('url')
                listcontent.append(obj)
        return listcontent

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
            "last_update": self.delta}
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
