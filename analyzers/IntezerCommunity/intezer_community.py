#!/usr/bin/env python3

import requests
import time
import os

from cortexutils.analyzer import Analyzer


class IntezerCommunityAnalyzer(Analyzer):
    """
    Intezer Community APIs: https://analyze.intezer.com/api/docs/documentation
    """

    def run(self):

        try:

            if self.data_type == 'file':
                api_key = self.get_param('config.key', None, 'Missing Intezer API key')
                filepath = self.get_param('file', None, 'File is missing')
                filename = self.get_param('filename', os.path.basename(filepath))

                base_url = 'https://analyze.intezer.com/api/v2-0'
                # this should be done just once in a day, but we cannot do that with Cortex Analyzers
                response = requests.post(base_url + '/get-access-token', json={'api_key': api_key})
                response.raise_for_status()
                session = requests.session()
                session.headers['Authorization'] = session.headers['Authorization'] = 'Bearer %s' % response.json()[
                    'result']

                with open(filepath, 'rb') as file_to_upload:
                    files = {'file': (filename, file_to_upload)}
                    response = session.post(base_url + '/analyze', files=files)
                    if response.status_code != 201:
                        self.error('Error sending file to Intezer Analyzer\n{}'.format(response.text))

                while response.status_code != 200:
                    time.sleep(3)
                    result_url = response.json()['result_url']
                    response = session.get(base_url + result_url)
                    response.raise_for_status()

                report = response.json()
                self.report(report)

            else:
                self.notSupported()

        except requests.HTTPError as e:
            self.error(e)
        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        taxonomies = []
        namespace = 'IntezerCommunity'

        if 'status' in raw and raw['status'] == 'succeeded':
            predicate = 'Analysis succeeded'
        else:
            predicate = 'Analysis failed'

        level = 'info'
        value = 'no family'
        if 'result' in raw:
            if 'verdict' in raw['result']:
                level = raw['result']['verdict']
                if level == 'trusted':
                    level = 'safe'
                if level not in ['info', 'safe', 'suspicious', 'malicious']:
                    level = 'info'
            if 'family_name' in raw['result']:
                value = raw['result']['family_name']

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {'taxonomies': taxonomies}


if __name__ == '__main__':
    IntezerCommunityAnalyzer().run()
