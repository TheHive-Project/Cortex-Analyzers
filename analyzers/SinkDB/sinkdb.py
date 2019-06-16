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
        proc = subprocess.Popen(['dig', '+short', '{}.{}.sinkdb-dnsapi.abuse.ch'.format(ip, self.apikey)],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        out, err = proc.communicate()
        out = out.decode('utf-8').split('\n')

        if err:
            self.error('Error while calling dig: {}.'.format(err))

        answers = []
        for ip in out:
            if ip == '127.0.1.0':
                answers.append("\"Known Sinkhole\"")
            elif ip == '127.0.2.0':
                answers.append("\"Phishing Awareness Campaign\"")
            elif ip == '127.0.3.0':
                answers.append("\"Known Scanner\"")
            else:
                continue

        return answers

    def run(self):
        self.report({
            'answers': self.dig(self.data)
        })

    def summary(self, raw):
        taxonomies = []

        if len(raw.get('answers')) > 0:
            for answer in raw.get('answers'):
                taxonomies.append(self.build_taxonomy('safe', 'SinkDB', 'Category', answer))
        else:
            taxonomies.append(self.build_taxonomy('suspicious', 'SinkDB', 'IsSinkhole', 'False'))
        return {
            "taxonomies": taxonomies
        }


if __name__ == '__main__':
    SinkDBAnalyzer().run()
