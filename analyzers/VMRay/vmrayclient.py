#!/usr/bin/env python

import base64
import os

from requests import sessions


class VMRayClientError(Exception):
    """Parent class for all specific errors used by VMRayClient."""
    pass


class UnknownHashTypeError(VMRayClientError):
    """Raised when length of hash as hex-string (or in bits) is not 32 (128 bit), 40 (160 bit) or 64 (256 bit)."""
    pass


class BadResponseError(VMRayClientError):
    """HTTP return status is not 200."""
    pass


class SampleFileNotFoundError(VMRayClientError):
    """Sample file was not found under given filepath."""
    pass


class UnknownSubmissionIdError(VMRayClientError):
    """Thrown on invalid submission id or if id request fails."""
    pass


class VMRayClient(object):
    """
    Client that connects to the VMRay api and allows searching for samples via hash and uploading a new sample to VMRay.

    :param url: Url to connect to
    :type url: str
    :param key: API Key
    :type key: str
    :param reanalyze: Force reanalyzation. VMRay does not provide additional information if sample has already been
                      uploaded, so this could be useful to obtain information. **Default: True**
    :type reanalyze: bool
    :param verify: Certificate for ssl validation in case the server certificate is self-signed. **Default: True**
    :type verify: [bool, str]
    """
    def __init__(self, url, key, reanalyze=True, verify=True):
        self.url = url
        self.key = key
        self.reanalyze = reanalyze
        self.headers = self._prepare_headers()
        self.session = sessions.Session()
        self.session.headers = self.headers
        self.session.verify = verify

    def _prepare_headers(self):
        """Prepares connection headers for authorization.

        :returns: Dict with HTTP headers
        :rtype: dict"""
        headers = {'Authorization': 'api_key {}'.format(self.key)}
        return headers

    def get_sample(self, samplehash):
        """
        Downloads information about a sample using a given hash.

        :param samplehash: hash to search for. Has to be either md5, sha1 or sha256
        :type samplehash: str
        :returns: List of samples
        :rtype: list(dict)
        """
        if len(samplehash) == 32:  # MD5
            hashtype = 'md5'
        elif len(samplehash) == 40:  # SHA1
            hashtype = 'sha1'
        elif len(samplehash) == 64:  # SHA256
            hashtype = 'sha256'
        else:
            raise UnknownHashTypeError('Sample hash has an unknown length.')

        apiurl = '/rest/sample/{}/{}'.format(hashtype, samplehash)
        res = self.session.get('{}{}'.format(self.url, apiurl))
        if res.status_code == 200:
            sample = res.json()
            if sample.get('result') == 'ok':
                return sample.get('data', [])
            else:
                raise RuntimeError('Error from VMRay via API.'
                                   ' Errors: {}'.format('; '.join(sample['data']['errors'])))
        else:
            raise BadResponseError('Response from VMRay was not HTTP 200.'
                                   ' Responsecode: {}; Text: {}'.format(res.status_code, res.text))

    def submit_sample(self, filepath, filename, tags=['TheHive']):
        """
        Uploads a new sample to VMRay api. Filename gets sent base64 encoded.

        :param filepath: path to sample
        :type filepath: str
        :param filename: filename of the original file
        :type filename: str
        :param tags: List of tags to apply to the sample
        :type tags: list(str)
        :returns: List of submissions and samples
        :rtype: list(dict)
        """
        apiurl = '/rest/sample/submit?sample_file'
        params = {'sample_filename_b64enc': base64.b64encode(filename.encode('utf-8')),
                  'reanalyze': self.reanalyze}
        if tags:
            params['tags'] = ','.join(tags)

        if os.path.isfile(filepath):
            res = self.session.post(url='{}{}'.format(self.url, apiurl),
                                    files=[('sample_file', open(filepath, mode='rb'))],
                                    params=params)
            if res.status_code == 200:
                submit_report = res.json()
                if submit_report.get('result') == 'ok':
                    return submit_report.get('data', [])
                else:
                    raise RuntimeError('Error from VMRay via API.'
                                    ' Errors: {}'.format('; '.join(submit_report['data']['errors'])))
            else:
                raise BadResponseError('Response from VMRay was not HTTP 200.'
                                       ' Responsecode: {}; Text: {}'.format(res.status_code, res.text))
        else:
            raise SampleFileNotFoundError('Given sample file was not found.')

    def get_sample_threat_indicators(self, sampleid):
        """
        Download Threat Indicators for a given sample id.

        :param sampleid: ID of the sample
        :type sampleid: int
        :returns: Dictionary of Threat Indicators
        :rtype: dict
        """
        apiurl = '/rest/sample/{}/threat_indicators'.format(sampleid)
        res = self.session.get('{}{}'.format(self.url, apiurl))
        if res.status_code == 200:
            threat_indicators = res.json()
            if threat_indicators.get('result') == 'ok':
                return threat_indicators.get('data', {})
            else:
                raise RuntimeError('Error from VMRay via API.'
                                   ' Errors: {}'.format('; '.join(threat_indicators['data']['errors'])))
        else:
            raise BadResponseError('Response from VMRay was not HTTP 200.'
                                   ' Status Code: {}; Text: {}'.format(res.status_code, res.text))

    def get_sample_mitre_attack(self, sampleid):
        """
        Download MITRE ATT&CK(tm) information for a given sample id.

        :param sampleid: ID of the sample
        :type sampleid: int
        :returns: Dictionary of MITRE ATT&CK(tm) information
        :rtype: dict
        """
        apiurl = '/rest/sample/{}/mitre_attack'.format(sampleid)
        res = self.session.get('{}{}'.format(self.url, apiurl))
        if res.status_code == 200:
            mitre_attack = res.json()
            if mitre_attack.get('result') == 'ok':
                return mitre_attack.get('data', {})
            else:
                raise RuntimeError('Error from VMRay via API.'
                                   ' Errors: {}'.format('; '.join(mitre_attack['data']['errors'])))
        else:
            raise BadResponseError('Response from VMRay was not HTTP 200.'
                                   ' Status Code: {}; Text: {}'.format(res.status_code, res.text))

    def get_sample_iocs(self, sampleid):
        """
        Download IOCs for a given sample id.

        :param sampleid: ID of the sample
        :type sampleid: int
        :returns: Dictionary of IOCs
        :rtype: dict
        """
        apiurl = '/rest/sample/{}/iocs'.format(sampleid)
        res = self.session.get('{}{}'.format(self.url, apiurl))
        if res.status_code == 200:
            iocs = res.json()
            if iocs.get('result') == 'ok':
                return iocs.get('data', {})
            else:
                raise RuntimeError('Error from VMRay via API.'
                                   ' Errors: {}'.format('; '.join(iocs['data']['errors'])))
        else:
            raise BadResponseError('Response from VMRay was not HTTP 200.'
                                   ' Status Code: {}; Text: {}'.format(res.status_code, res.text))

    def query_job_status(self, submissionid):
        """
        Queries vmray to check id a job was 
        
        :param submissionid: ID of the job/submission
        :type submissionid: int
        :returns: True if job finished, false if not
        :rtype: bool
        """
        apiurl = '/rest/submission/{}'.format(submissionid)
        res = self.session.get('{}{}'.format(self.url, apiurl))
        if res.status_code == 200:
            submission_info = res.json()
            if submission_info.get('data', {}).get('submission_finished', False):  # Or something like that
                return True
        else:
            raise UnknownSubmissionIdError('Submission id seems invalid, response was not HTTP 200.')
        return False

    def query_sample_submissions(self, sampleid):
        """
        Queries submissions for a given sample id.

        :param sampleid: ID of the sample
        :type sampleid: int
        :returns: List of submissions
        :rtype: list(dict)
        """
        apiurl = '/rest/submission/sample/{}'.format(sampleid)
        res = self.session.get('{}{}'.format(self.url, apiurl))
        if res.status_code == 200:
            submissions = res.json()
            if submissions.get('result') == 'ok':
                return submissions.get('data', [])
            else:
                raise RuntimeError('Error from VMRay via API.'
                                   ' Errors: {}'.format('; '.join(submissions['data']['errors'])))
        else:
            raise BadResponseError('Response from VMRay was not HTTP 200.'
                                   ' Status Code: {}; Text: {}'.format(res.status_code, res.text))

    def get_submission_analyses(self, submissionid):
        """
        Downloads analyses about a sample using a given submission id.

        :param submissionid: ID of the job/submission
        :type submissionid: int
        :returns: List of analyses
        :rtype: list(dict)
        """
        apiurl = '/rest/analysis/submission/{}'.format(submissionid)
        res = self.session.get('{}{}'.format(self.url, apiurl))
        if res.status_code == 200:
            analyses = res.json()
            if analyses.get('result') == 'ok':
                return analyses.get('data', [])
            else:
                raise RuntimeError('Error from VMRay via API.'
                                   ' Errors: {}'.format('; '.join(analyses['data']['errors'])))
        else:
            raise UnknownSubmissionIdError('Submission id seems invalid, response was not HTTP 200.')
