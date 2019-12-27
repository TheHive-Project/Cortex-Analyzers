#!/usr/bin/env python3
# encoding: utf-8


from cortexutils.responder import Responder
import re
import requests


class CloseAlert(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.data = self.get_param('data', None, 'Data is missing')
        self.url = self.get_param('config.url', None, 'url is missing')
        self.api = self.get_param('config.api', None, 'api key is missing')

        # Action for Zerofox Alert : see "POST /alerts/{alert_id}/{action}/" on https://api.zerofox.com/1.0/docs/
        self.zfEntity = "alerts"
        self.zfAction = "close"


    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='TheHive:Responders=Zerofox Alert Closed')]

    def ZerofoxAlert(self, tags):
        """

        :param tags: list
        :return: bool
        """
        zfalert="src:ZEROFOX"
        if tags:
            for tag in tags:
                zf_id = re.match("^ZF:Id=(\d+)", tag)
                if zf_id and zfalert in tags:
                    return zf_id.group(1)
        return 0


    def run(self):
        Responder.run(self)
        tags = self.get_param('data.tags', None)
        action_request = "{}/{}/{}/{}/".format(self.url, self.zfEntity, self.ZerofoxAlert(tags), self.zfAction)


        # Manage mail addresses
        if self.data_type == 'thehive:case':
            if self.ZerofoxAlert(tags):
                try:
                    response = requests.post(action_request, headers={'Authorization':
                                              'Token {}'.format(self.api)})
                    if response.status_code == 200:
                        self.report({'message': 'Alert {} has been closed'.format(self.ZerofoxAlert(tags))})
                    elif response.status_code == 400:
                        self.error('HTTP 400 : Request body schema error')
                except Exception as ex:
                    self.error(ex)

if __name__ == '__main__':
    CloseAlert().run()
