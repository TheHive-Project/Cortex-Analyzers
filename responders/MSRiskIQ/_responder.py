#!/usr/bin/env python3
# encoding: utf-8
 

from cortexutils.responder import Responder
from _services import SERVICES



class RiskIQIlluminate(Responder):
    def __init__(self):
        Responder.__init__(self)
        self._username = self.get_param('config.username', None, 'RiskIQ Illuminate username is missing')
        self._api_key = self.get_param('config.api_key', None, 'RiskIQ Illuminate api_key is missing')
        self._service_name = self.get_param('config.service', None, 'Service name is required')
        self._project_visibility = self.get_param('config.project_visiblity','analyst')
        self._project_prefix = self.get_param('config.project_prefix', 'Hive:')
        self._thehive_artifact_tag = self.get_param('config.thehive_artifact_tag',None)
        self._riq_artifact_tag = self.get_param('config.riq_artifact_tag',None)
        self._service = SERVICES[self._service_name](
            visibility = self._project_visibility,
            prefix = self._project_prefix,
            thehive_artifact_tag = self._thehive_artifact_tag,
            riq_artifact_tag = self._riq_artifact_tag,
            username = self._username,
            api_key = self._api_key
        )
    
    def run(self):
        Responder.run(self)
        self._service.run(self.get_param('data'))
        report = self._service.get_report()
        if 'error' in report:
            self.error(report['error'])
        self.report(report)

    def operations(self, raw):
        ops = []
        for op in self._service.get_operations():
            ops.append(self.build_operation(op['name'], **op['kwargs']))
        return ops



if __name__ == '__main__':
    RiskIQIlluminate().run()