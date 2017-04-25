#!/usr/bin/env python
from cortexutils.analyzer import Analyzer
from vmrayclient import VMRayClient


class VMRayAnalyzer(Analyzer):
    """
    VMRay analyzer that uses VMRayClient to connect to an VMRay instance. Allows uploading a sample and getting
    information via hash. More info regarding configuration in the complete documentation.
    """
    def __init__(self):
        Analyzer.__init__(self)
        self.url = self.getParam('config.url', None, 'No VMRay url given.').rstrip('/ ')
        disable_reanalyze = self.getParam('config.disablereanalyze', False)
        if disable_reanalyze == 'true' or disable_reanalyze:
            reanalyze = False
        else:
            reanalyze = True
        self.vmrc = VMRayClient(url=self.url,
                                key=self.getParam('config.key', None, 'No VMRay API key given.'),
                                cert=self.getParam('config.certpath', True),
                                reanalyze=reanalyze)

    def run(self):
        if self.data_type == 'hash':
            self.report({'scanreport': self.vmrc.get_sample(self.getData())})
        elif self.data_type == 'file':
            filepath = self.getParam('file')
            filename = self.getParam('filename')
            self.report(self.vmrc.submit_sample(filepath=filepath,
                                                filename=filename))
        else:
            self.error('Data type currently not supported')

    def summary(self, raw):
        result = {
            'reports': [],
            'submits': []
        }
        if raw.get('scanreport', None) and len(raw.get('scanreport').get('data')) > 0:
            for scan in raw.get('scanreport').get('data'):
                result['reports'].append({
                    'score': scan.get('sample_score'),
                    'url': scan.get('sample_webif_url')
                })
        elif raw.get('data', None) and len(raw.get('data').get('submissions')) > 0:
            for subm in raw.get('data').get('submissions'):
                result['submits'].append({
                    'id': subm.get('submission_sample_id'),
                    'url': subm.get('submission_webif_url')
                })

        return result

if __name__ == '__main__':
    VMRayAnalyzer().run()
