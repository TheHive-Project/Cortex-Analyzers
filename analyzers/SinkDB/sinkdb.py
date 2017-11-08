#!/usr/bin/env python
import subprocess

from cortexutils.analyzer import Analyzer


class SinkDBAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        if self.data_type != 'ip':
            self.error('SinkDB Analyzer only usable with ip data type.')

        self.apikey = self.get_param('config.key', None, 'API Key needed for querying SinkDB.')
        self.data = self.get_data().split('.')
        self.data.reverse()
        self.data = '.'.join(self.data)

    def dig(self, ip):
        proc = subprocess.Popen(['dig', '+short', '{}.{}.sinkdb-api.abuse.ch'.format(ip, self.apikey)],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        out, err = proc.communicate()
        out = out.decode('utf-8').strip('\n')

        if err:
            self.error('Error while calling dig: {}.'.format(err))

        if out == '127.0.0.2':
            return True

        return False

    def run(self):
        self.report({
            "is_sinkhole": self.dig(self.data)
        })

    def summary(self, raw):
        taxonomies = []

        if raw.get('is_sinkhole'):
            taxonomies.append(self.build_taxonomy('safe', 'SinkDB', 'IsSinkhole', 'True'))
        else:
            taxonomies.append(self.build_taxonomy('suspicious', 'SinkDB', 'IsSinkhole', 'False'))
        return {
            "taxonomies": taxonomies
        }


if __name__ == '__main__':
    SinkDBAnalyzer().run()
