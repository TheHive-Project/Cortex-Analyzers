#!/usr/bin/env python3
# encoding: utf-8
import requests
from cortexutils.analyzer import Analyzer


class HashddAnalyzer(Analyzer):
    service = 'Status'
    url = 'https://api.hashdd.com/'
    hashdd_key = None

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')

        if self.service == "status":
            self.url = 'https://api.hashdd.com/'
        elif self.service == "detail":
            self.hashdd_key = self.get_param('config.api_key', None, 'Missing hashdd API key')
            self.url = 'https://api.hashdd.com/detail'

    def hashdd_check(self, data):
        if self.hashdd_key is None:
            postdata = {'hash': self.get_data()}
        else:
            postdata = {'hash': self.get_data(), 'api_key': self.hashdd_key}

        r = requests.post(self.url, data=postdata)
        r.raise_for_status()  # Raise exception on HTTP errors
        return r.json()

    def summary(self, raw):
        taxonomies = []
        namespace = 'Hashdd'
        predicate = 'known_level'
        value = "0"

        level = 'info'  # Default level: this assigned when known_level is unknown

        if 'known_level' in raw:
            known_level = raw['known_level']
            if known_level == 'Good':
                level = "safe"
            elif known_level == 'Bad':
                level = "malicious"
            # else:
            #     level = "suspicious" # this one is not used

            value = "{}".format(known_level)  # Value must be enclosed with double quotes

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type != 'hash':
            self.notSupported()

        data = self.get_param('data', None, 'Data is missing')
        hash = data.upper()

        response = self.hashdd_check(data)

        if response['result'] == 'SUCCESS':

            if self.service == "status":
                self.report({
                    'known_level': response[hash]['known_level']
                })
            elif self.service == "detail":
                if response.get(hash).get('result') != "NOT_FOUND":
                    self.report({
                        'known_level': response[hash]['summary']['hashdd_known_level'],
                        'file_name': response[hash]['summary']['hashdd_file_name'],
                        'file_absolute_path': response[hash]['summary']['hashdd_file_absolute_path'],
                        'size': response[hash]['summary']['hashdd_size'],
                        'product_manufacturer': response[hash]['summary']['hashdd_product_manufacturer'],
                        'product_name': response[hash]['summary']['hashdd_product_name'],
                        'product_version': response[hash]['summary']['hashdd_product_version'],
                        'architecture': response[hash]['summary']['hashdd_architecture'],
                        'md5': response[hash]['summary']['hashdd_md5'],
                        'sha1': response[hash]['summary']['hashdd_sha1'],
                        'sha256': response[hash]['summary']['hashdd_sha256'],
                        'ssdeep': response[hash]['summary']['hashdd_ssdeep']
                    })
                else:
                    self.report({'known_level':'Unknown'})

        else:
            self.error('{}'.format(response['result']))


if __name__ == '__main__':
    HashddAnalyzer().run()
