#!/usr/bin/env python3

from urllib.parse import urlsplit
from mimecast_api import MimecastAPI, URLDecodeFail
from cortexutils.analyzer import Analyzer

class MimecastAnalyzer(Analyzer):
    def __init__(self):
        super().__init__()
        self.service = self.get_param('config.service', None,
                                      'Service parameter is missing')
        mimecast_config = {
            'base_url': self.get_param('config.base_url', None,
                                       'Mimecast API base URL is missing'),
            'app_id': self.get_param('config.app_id', None,
                                     'App ID is missing'),
            'app_key': self.get_param('config.app_key', None,
                                      'App key is missing'),
            'access_key': self.get_param('config.access_key', None,
                                         'Access key is missing'),
            'secret_key': self.get_param('config.secret_key', None,
                                         'Secret key is missing'),
            }
        self.mimecast_api = MimecastAPI(**mimecast_config)

    def _looks_like_mimecast_protected_url(self, url):
        pieces = urlsplit(url)
        return (pieces.scheme == 'https' and
                pieces.netloc.startswith('protect-') and
                pieces.netloc.endswith('.mimecast.com'))

    def artifacts(self, raw):
        if self.service == 'decode_url':
            if 'decoded_url' in raw:
                return [{'type': 'url', 'value': raw['decoded_url']}]
            else:
                return []
        elif self.service == 'list_recent_recipients_from':
            if 'recipients' in raw:
                return [self.build_artifact('mail', recipient_address,
                                            tags=['recipient'])
                        for recipient_address in raw['recipients']]
            else:
                return []
        else:
            return []


    def summary(self, raw):
        if self.service == 'decode_url':
            if 'decoded_url' in raw:
                # it was a URL Protect URL
                return {'taxonomies': [
                    self.build_taxonomy('info', 'MC', 'URLProtect', 'True')]}
            else:
                return {}
        elif self.service == 'list_recent_recipients_from':
            if 'recipients' in raw:
                return {'taxonomies': [
                    self.build_taxonomy('info', 'MC', 'MessagesSentToUs',
                                        len(raw['recipients']))]}
            else:
                return {}
        else:
            return {}

    def run(self):
        super().run()
        try:
            if self.data_type == 'url':
                url = self.get_data()
                if self.service == 'decode_url':
                    if self._looks_like_mimecast_protected_url(url):
                        try:
                            decoded = self.mimecast_api.decode_url(url)
                            self.report({"decoded_url": decoded})
                        except URLDecodeFail as e:
                            self.report({"undecodable": repr(e)})
                    else:
                        self.report({"invalid":
                                     "does not look like a Mimecast-protected URL"})
                else:
                    self.notSupported()
            elif self.data_type == 'mail':
                email_address = self.get_data()
                if self.service == 'list_recent_recipients_from':
                    since_days_ago = self.get_param(
                        'config.find_messages_since_days_ago', 2,
                        'find_messages_since_days_ago parameter is missing')
                    recipients = self.mimecast_api.list_recent_recipients_from(
                        email_address, since_days_ago)
                    self.report({"recipients": recipients})
            else:
                self.notSupported()
        except Exception as e:
            self.unexpectedError("Unhandled exception: " + repr(e))


if __name__ == '__main__':
    MimecastAnalyzer().run()
