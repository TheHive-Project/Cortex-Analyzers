#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from vmrayclient import VMRayClient
from time import sleep


SEVERITY_MAPPING = {
    'whitelisted':      "safe",
    'not_suspicious':   "safe",
    'suspicious':       "suspicious",
    'malicious':        "malicious",
    'blacklisted':      "malicious",
}


class VMRayAnalyzer(Analyzer):
    """
    VMRay analyzer that uses VMRayClient to connect to an VMRay instance. Allows uploading a sample and getting
    information via hash. More info regarding configuration in the complete documentation.
    """
    def __init__(self):
        Analyzer.__init__(self)
        self.url = self.get_param('config.url', None, 'No VMRay URL given.').rstrip('/ ')
        self.key = self.get_param('config.key', None, 'No VMRay API key given.')

        self.disable_reanalyze = self.get_param('config.disablereanalyze', False)
        if isinstance(self.disable_reanalyze, str): # Check for string and boolean True
            self.disable_reanalyze = self.disable_reanalyze.lower() == 'true'
        if self.disable_reanalyze:
            reanalyze = False
        else:
            reanalyze = True

        verify = self.get_param('config.certverify', True)
        certpath = self.get_param('config.certpath', None)
        if verify and certpath:
            verify = certpath

        self.vmrc = VMRayClient(url=self.url,
                                key=self.key,
                                reanalyze=reanalyze,
                                verify=verify)

    def build_report(self, samplehash, submissionid=None):
        samples = self.vmrc.get_sample(samplehash)

        for s in samples:
            sampleid = s.get('sample_id')
            if not submissionid:
                submissions = self.vmrc.query_sample_submissions(sampleid)
                for submission in submissions:
                    if submission.get('submission_type') == 'api':
                        submissionid = submission.get('submission_id')
                        break

            s['sample_submission_analyses'] = self.vmrc.get_submission_analyses(submissionid)
            s['sample_threat_indicators'] = self.vmrc.get_sample_threat_indicators(sampleid)
            s['sample_mitre_attack'] = self.vmrc.get_sample_mitre_attack(sampleid)
            s['sample_iocs'] = self.vmrc.get_sample_iocs(sampleid)

        return {'samples': samples}

    def run(self):
        if self.data_type == 'hash':
            self.report(self.build_report(self.get_data()))
        elif self.data_type == 'file':
            filepath = self.get_param('file')
            filename = self.get_param('filename')
            submit_report = self.vmrc.submit_sample(filepath=filepath,
                                                    filename=filename)

            # Ref: #332: check if job was submitted
            if self.disable_reanalyze:
                if len(submit_report['errors']) > 0:
                    # Sample is already there, get the report
                    self.report(self.build_report(submit_report['samples'][0]['sample_sha256hash']))
                    return # stop waiting for report, because we already have it

            # Check for completion
            while not self.vmrc.query_job_status(submit_report['submissions'][0]['submission_id']):
                sleep(10)

            # Return the results
            self.report(self.build_report(submit_report['submissions'][0]['submission_sample_sha256'],
                                          submit_report['submissions'][0]['submission_id']))
        else:
            self.error('Data type currently not supported')

    def summary(self, raw):
        taxonomies = []

        namespace = "VMRay"
        predicate = "Score"

        samples = raw.get('samples', [])

        if len(samples) == 0:
            level = "info"
            value = "No Scan"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        else:
            for i, s in enumerate(samples, start=1):
                level = SEVERITY_MAPPING.get(s.get('sample_severity'), "info")
                value = "{}".format(s.get('sample_score'))
                if len(samples) > 1:
                    value += " (from scan {})".format(i)
                taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

                for ti in s.get('sample_threat_indicators', {}).get('threat_indicators', []):
                    predicate = ti.get('category', None)
                    value = ti.get('operation', None)
                    if predicate and value:
                        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []

        samples = raw.get('samples', [])

        for s in samples:
            link = s.get('sample_webif_url', None)
            iocs = s.get('sample_iocs', {}).get('iocs', {})

            for f in iocs.get('files', []):
                severity = f.get('severity')
                level = SEVERITY_MAPPING.get(severity, "info")
                tags = list({severity, level, f.get('type')})
                for hashes in f.get('hashes', []):
                    for h in hashes.values():
                        if not h: continue
                        artifacts.append(self.build_artifact("hash", h, message=link, tags=tags))

            for u in iocs.get('urls', []):
                severity = u.get('severity')
                level = SEVERITY_MAPPING.get(severity, "info")
                tags = list({severity, level, u.get('type')})
                artifacts.append(self.build_artifact("url", u.get('url'), message=link, tags=tags))

        return artifacts

if __name__ == '__main__':
    VMRayAnalyzer().run()
