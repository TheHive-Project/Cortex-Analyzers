#!/usr/bin/env python3
import traceback
import datetime
from cortexutils.responder import Responder
from mimecast_api import MimecastAPI

class MimecastResponder(Responder):
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

    def operations(self, raw):
        out = []
        if 'blocked' in raw:
            out.append(self.build_operation('AddTagToArtifact',
                                            tag=f"MC:Blocked={raw['blocked']}"))
        return out

    def run(self):
        super().run()
        # I tried supporting 'domain' typed observables too, but the
        # Mimecast API seemed to want a whole URL, not just a DNS
        # name, even for domain blocks.
        if self.get_param('data.dataType') == 'url':
            url = self.get_param('data.data', None, 'No url found')
        else:
            self.error('Only url dataType is supported for this operation')
        if self.service == 'block_url':
            thing = 'URL'
            only_match_domain_blocks = False
            block_type = 'explicit'
        elif self.service == 'block_domain':
            thing = 'Domain'
            only_match_domain_blocks = True
            block_type = 'domain'
        else:
            self.error(f'Unknown service {self.service}')
        try:
            managed = self.mimecast_api.is_url_managed(
                url, only_match_domain_blocks=only_match_domain_blocks)
            if managed:
                if managed['action'] == 'block':
                    self.report({"message": f"{thing} is already blocked",
                                 "matchType": managed['matchType'],
                                 "action": managed['action'],
                                 "comment": managed['comment'],
                                 "blocked": managed['matchType']})
                else:
                    # this request conflicts with previous direction given
                    # to Mimecast, so make an error
                    #
                    # unfortunately i don't think you can fail to run
                    # and also render a report visible in the hive. so
                    # this failure will always result in an empty
                    # report and you'll only see this message if you
                    # go into cortex
                    self.error(thing + " is already managed: matched by {matchType}, action {action}, comment {comment!r}. Nothing done. Visit Mimecast's website manually.".format(managed))
            else:
                case_number = self.get_param('data.case.caseId', None)
                if case_number:
                    comment = f"Hive #{case_number}"
                else:
                    now = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%S+0000')
                    comment = f"Cyber threat response #{now}"
                now_managed = self.mimecast_api.block_url(url, block_type, comment)
                self.report({"message": f"{thing} block added with comment {comment!r}",
                             "blocked": now_managed['matchType']})
        except Exception as e:
            # expected errors would have been handled with self.error
            self.error('Unexpected exception:\n'+traceback.format_exc())


if __name__ == '__main__':
    MimecastResponder().run()
