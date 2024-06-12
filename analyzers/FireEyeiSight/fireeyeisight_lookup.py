#!/usr/bin/env python3
# encoding: utf-8
import requests
import hashlib
import hmac
import email
from datetime import datetime, date

from cortexutils.analyzer import Analyzer


class APIRequestHandler(object):
    def __init__(self, public_key, private_key):
        self.URL = 'https://api.isightpartners.com'
        self.public_key = public_key
        self.private_key = private_key
        self.accept_version = '2.5'

    def exec_query(self, endpoint):
        time_stamp = email.utils.formatdate(localtime=True)
        accept_header = 'application/json'
        new_data = endpoint + self.accept_version + accept_header + time_stamp

        key = bytearray()
        key.extend(map(ord, self.private_key))
        hashed = hmac.new(key, new_data.encode('utf-8'), hashlib.sha256)

        headers = {
            'Accept': accept_header,
            'Accept-Version': self.accept_version,
            'X-Auth': self.public_key,
            'X-Auth-Hash': hashed.hexdigest(),
            'Date': time_stamp,
        }

        r = requests.get(self.URL + endpoint, headers=headers)

        if r.status_code == 200:
            return r.json()
        else:
            return -1


class FireEyeiSightAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            'config.service', None, 'Service parameter is missing')
        self.key = self.get_param('config.key', None, 'Missing API key')
        self.pwd = self.get_param('config.pwd', None, 'Missing API password')
        self.request_handler = APIRequestHandler(self.key, self.pwd)

    def cleanup(self, data_info=[]):
        response = {
            'level': 'no-info',
            'score': 0,
            'domain': [],
            'ip': [],
            'md5': [],
            'sha1': [],
            'sha256': [],
            'intelligenceType': [],
            'webLink': [],
            'identifier': [],
            'observationTime': [],
            'ThreatScape': [],
            'title': [],
            'size': [],
            'fileName': [],
            'packer': [],
            'actor': [],
            'report_data': []
        }

        json_fields = ['domain', 'intelligenceType', 'ip', 'title', 'webLink', 'observationTime', 'ThreatScape', 'sha1',
                       'sha256', 'md5', 'size', 'fileName', 'packer', 'actor']
        json_unique_fields = ['domain', 'ip', 'sha1', 'sha256', 'md5', 'size', 'fileName', 'packer', 'actor']

        for report in data_info:

            identifier = report.get('fileIdentifier', None) if self.data_type == 'hash' else report.get(
                'networkIdentifier', None)
            if identifier and identifier not in response['identifier']:
                response['identifier'].append(identifier)

            for field in json_fields:
                field_value = report.get(field, None)
                if field == 'observationTime':
                    field_value = datetime.fromtimestamp(field_value).strftime('%Y-%m-%d %H:%M:%S')
                if field_value and field in json_unique_fields and field_value not in response[field]:
                    response[field].append(field_value)
                elif field_value and field not in json_unique_fields:
                    response[field].append(field_value)

        for identifier in response['identifier']:
            if identifier in ['Attacker', 'Compromised']:
                response['level'] = 'malicious'
            elif identifier in ['Victim', 'Related'] and response['level'] != 'malicious':
                response['level'] = 'safe'

        for i in range(len(data_info)):
            response['report_data'].append({'title': response['title'][i],
                                            'threatScape': response['ThreatScape'][i],
                                            'intelligenceType': response['intelligenceType'][i],
                                            'webLink': response['webLink'][i],
                                            'observationTime': response['observationTime'][i]})

        response['score'] = len(data_info)

        del response['title']
        del response['ThreatScape']
        del response['webLink']
        del response['observationTime']
        del response['intelligenceType']

        return response

    def query(self, data):
        results = dict()
        try:
            r = self.request_handler.exec_query('/search/text?text=%s' % data)
            report_ids = [x.get('reportId', None) for x in r['message']] if r != -1 else []
            data_info = []
            for report in report_ids:
                r = self.request_handler.exec_query('/pivot/report/%s/indicator' % report)
                if self.data_type == 'domain':
                    tmp_info = [x for x in r['message'].get('publishedIndicators', [])
                                if x.get('domain', None) == data] if r != -1 else []
                elif self.data_type == 'hash':
                    tmp_info = [x for x in r['message'].get('publishedIndicators', [])
                                if x.get('md5', None) == data or x.get('sha1', None) == data
                                or x.get('sha256', None) == data] if r != -1 else []
                elif self.data_type == 'ip':
                    tmp_info = [x for x in r['message'].get('publishedIndicators', [])
                                if x.get('ip', None) == data] if r != -1 else []
                if tmp_info:
                    for x in tmp_info:
                        tmp_dict = {k: v for k, v in x.items() if v}
                        if tmp_dict not in data_info:
                            data_info.append(tmp_dict)
            return self.cleanup(data_info)
        except Exception as e:
            self.error("OS error: {0}".format(e))
        return results

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "FireEyeiSight"
        predicate = "Report"
        score = raw['score']
        level = raw['level']
        if score > 0:
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, score))
        return {"taxonomies": taxonomies}

    def run(self):

        if self.service == 'query':
            data = self.get_param('data', None, 'Data is missing')
            if self.data_type in ['domain', 'url', 'hash', 'ip']:
                rep = self.query(data)
                self.report(rep)
            else:
                self.error('Invalid data type')
        else:
            self.error('Invalid service')


if __name__ == '__main__':
    FireEyeiSightAnalyzer().run()
