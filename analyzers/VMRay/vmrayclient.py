#!/usr/bin/env python
import base64
import json
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


class VMRayClient:
    """
    Client that connects to the VMRay api and allows searching for samples via hash and uploading a new sample to VMRay.

    :param url: Url to connect to
    :type url: str
    :param key: API Key
    :type key: str
    :param cert: Certificate for ssl validation in case the server certificate is self-signed. **Default: True**
    :type cert: [bool, str]
    :param reanalyze: Force reanalyzation. VMRay does not provide additional information if sample has already been
                      uploaded, so this could be useful to obtain information. **Default: True**
    :type reanalyze: bool
    """
    def __init__(self, url, key, cert=True, reanalyze=True):
        self.url = url
        self.key = key
        if cert and os.path.isfile(cert):
            self.cert = cert
        else:
            self.cert = False
        self.reanalyze = reanalyze
        self.headers = self._prepare_headers()
        self.session = sessions.Session()
        self.session.headers = self.headers
        self.session.verify = self.cert

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
        :returns: Dictionary of results
        :rtype: dict
        """
        apiurl = '/rest/sample/'
        if len(samplehash) == 32:  # MD5
            apiurl += 'md5/'
        elif len(samplehash) == 40:  # SHA1
            apiurl += 'sha1/'
        elif len(samplehash) == 64:  # SHA256
            apiurl += 'sha256/'
        else:
            raise UnknownHashTypeError('Sample hash has an unknown length.')

        res = self.session.get(self.url + apiurl + samplehash)
        if res.status_code == 200:
            return json.loads(res.text)
        else:
            raise BadResponseError('Response from VMRay was not HTTP 200.'
                                   ' Responsecode: {}; Text: {}'.format(res.status_code, res.text))

    def submit_sample(self, filepath, filename, tags=['JAMIE_Import', 'TheHive_Import']):
        """
        Uploads a new sample to VMRay api. Filename gets sent base64 encoded.

        :param filepath: path to sample
        :type filepath: str
        :param filename: filename of the original file
        :type filename: str
        :param tags: List of tags to apply to the sample
        :type tags: list(str)
        :returns: Dictionary of results
        :rtype: dict
        """
        apiurl = '/rest/sample/submit?sample_file'
        params = {'sample_filename_b64enc': base64.b64encode(filename.encode('utf-8')),
                  'reanalyze': self.reanalyze}
        if tags:
            params['tags'] = ','.join(tags)

        if os.path.isfile(filepath):
            res = self.session.post(url=self.url + apiurl,
                                    files=[('sample_file', open(filepath, mode='rb'))],
                                    params=params)
            if res.status_code == 200:
                return json.loads(res.text)
            else:
                raise BadResponseError('Response from VMRay was not HTTP 200.'
                                       ' Responsecode: {}; Text: {}'.format(res.status_code, res.text))
        else:
            raise SampleFileNotFoundError('Given sample file was not found.')

    def query_job_status(self, submissionid):
        """
        Queries vmray to check id a job was 
        
        :param submissionid: ID of the job/submission
        :type submissionid: int
        :returns: True if job finished, false if not
        :rtype: bool
        """

        apiurl = '/rest/submission/'
        result = self.session.get('{}{}{}'.format(self.url, apiurl, submissionid))
        if result.status_code == 200:
            submission_info = json.loads(result.text)
            if submission_info.get('data', {}).get('submission_finished', False):  # Or something like that
                return True
        else:
            raise UnknownSubmissionIdError('Submission id seems invalid, response was not HTTP 200.')
        return False
