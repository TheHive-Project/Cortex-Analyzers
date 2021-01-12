#!/usr/bin/env python

import base64
import json
import os

from requests import sessions


class VMRayClientError(Exception):
    """ Parent class for all specific errors used by VMRayClient. """

    pass


class VMRayAPIError(VMRayClientError):
    """ Raised in case the VMRay API returns an eror. """

    pass


class UnknownHashTypeError(VMRayClientError):
    """ Raised when length of hash as hex-string (or in bits) is not 32 (128 bit), 40 (160 bit) or 64 (256 bit). """

    pass


class BadResponseError(VMRayClientError):
    """ Raised in case the VMRay API returns a non-2xx status code. """

    pass


class SampleFileNotFoundError(VMRayClientError):
    """Sample file was not found under given filepath."""

    pass


def _filter_dict(data):
    return dict(filter(lambda item: item[1] is not None, data.items()))


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

    _submit_endpoint = "/rest/sample/submit"
    _submission_endpoint = "/rest/submission/{}"
    _sample_endpoint = "/rest/sample/{}"
    _sample_hash_endpoint = "/rest/sample/{t}/{h}"
    _sample_analyses_endpoint = "/rest/analysis/sample/{}"
    _sample_iocs_endpoint = "/rest/sample/{}/iocs"
    _sample_mitre_endpoint = "/rest/sample/{}/mitre_attack"
    _sample_threat_indicators_endpoint = "/rest/sample/{}/threat_indicators"
    _continuation_endpoint = "/rest/continuation/{}"

    def __init__(
        self,
        url,
        key,
        recursive_sample_limit=10,
        reanalyze=True,
        verify=True,
        **optional_parameters
    ):
        self.url = url
        self.key = key
        self.reanalyze = reanalyze
        self.recursive_sample_limit = recursive_sample_limit
        self.headers = self._prepare_headers()
        self.session = sessions.Session()
        self.session.headers = self.headers
        self.session.verify = verify
        self.optional_parameters = optional_parameters

    def _prepare_headers(self):
        """Prepares connection headers for authorization.

        :returns: Dict with HTTP headers
        :rtype: dict"""
        headers = {"Authorization": "api_key {}".format(self.key)}
        return headers

    def _check_response(self, res):
        """
        Check the response code of the API and either return the results or raise an error.
        """
        if res.status_code < 200 or res.status_code > 299:
            raise BadResponseError(
                "HTTP response code from VMRay indicates an error: {c} ({t})".format(
                    c=res.status_code, t=res.text
                )
            )
        else:
            response_json = res.json()
            if response_json.get("result") == "ok":
                data = response_json.get("data", [])
                if "continuation_id" in response_json:
                    result = self.session.get(
                        url="{}{}".format(
                            self.url,
                            self._continuation_endpoint.format(
                                response_json["continuation_id"]
                            ),
                        )
                    )
                    data.extend(self._check_response(result))
                return data
            else:
                error_content = "Error from VMRay via API: {}"
                if "data" in response_json:
                    error_content = error_content.format(
                        "; ".join(response_json["data"]["errors"])
                    )
                elif "error_msg" in response_json:
                    error_content = error_content.format(response_json["error_msg"])
                else:
                    error_content = error_content.format("Unspecified error occurred")
                raise VMRayAPIError(error_content)

    def submit_url_sample(
        self, url_sample, tags=["TheHive"], shareable=False, user_config={}
    ):
        """
        Uploads a new URL sample to VMRay api.

        :param url_sample: url to be analyzed
        :type url_sample: str
        :param tags: List of tags to apply to the sample
        :type tags: list(str)
        :returns: List of submissions and samples
        :rtype: list(dict)
        """
        params = _filter_dict(self.optional_parameters)
        params.update(
            {
                "sample_url": url_sample,
                "reanalyze": self.reanalyze,
                "shareable": shareable,
                "max_recursive_samples": self.recursive_sample_limit,
            }
        )
        if tags:
            params["tags"] = ",".join(filter(None, tags))

        user_config = _filter_dict(user_config)
        if user_config:
            params["user_config"] = json.dumps(user_config)

        return self._check_response(
            self.session.post(
                url="{}{}".format(self.url, self._submit_endpoint),
                params=params,
            )
        )

    def submit_file_sample(
        self, file_path, file_name, tags=["TheHive"], shareable=False, user_config={}
    ):
        """
        Uploads a new file sample to VMRay API. Filename gets sent base64 encoded.

        :param file_path: path to sample
        :type file_path: str
        :param file_name: filename of the original file
        :type file_name: str
        :param tags: List of tags to apply to the sample
        :type tags: list(str)
        :returns: List of submissions and samples
        :rtype: list(dict)
        """
        params = _filter_dict(self.optional_parameters)
        params.update(
            {
                "sample_filename_b64enc": base64.b64encode(file_name.encode("utf-8")),
                "reanalyze": self.reanalyze,
                "shareable": shareable,
                "max_recursive_samples": self.recursive_sample_limit,
            }
        )
        if tags:
            params["tags"] = ",".join(filter(None, tags))

        user_config = _filter_dict(user_config)
        if user_config:
            params["user_config"] = json.dumps(user_config)

        if os.path.isfile(file_path):
            return self._check_response(
                self.session.post(
                    url="{}{}".format(self.url, self._submit_endpoint),
                    files=[("sample_file", open(file_path, mode="rb"))],
                    params=params,
                )
            )
        else:
            raise SampleFileNotFoundError("Given sample file was not found.")

    def get_sample_threat_indicators(self, sample_id):
        """
        Download Threat Indicators for a given sample id.

        :param sample_id: ID of the sample
        :type sample_id: int
        :returns: Dictionary of Threat Indicators
        :rtype: dict
        """
        return self._check_response(
            self.session.get(
                url="{}{}".format(
                    self.url, self._sample_threat_indicators_endpoint.format(sample_id)
                ),
            )
        )

    def get_sample_mitre_attack(self, sample_id):
        """
        Download MITRE ATT&CK(tm) information for a given sample id.

        :param sample_id: ID of the sample
        :type sample_id: int
        :returns: Dictionary of MITRE ATT&CK(tm) information
        :rtype: dict
        """

        return self._check_response(
            self.session.get(
                url="{}{}".format(
                    self.url, self._sample_mitre_endpoint.format(sample_id)
                ),
            )
        )

    def get_sample(self, sample_id):
        """
        Query sample with a given sample id.

        :param sample_id: ID of the sample
        :type sample_id: int
        :returns: Dictionary of Samples
        :rtype: dict
        """
        return self._check_response(
            self.session.get(
                url="{}{}".format(self.url, self._sample_endpoint.format(sample_id)),
            )
        )

    def get_samples_by_hash(self, sample_hash):
        """
        Downloads information about a all samplse matching the given hash.

        :param samplehash: hash to search for. Has to be either md5, sha1 or sha256
        :type samplehash: str
        :returns: List of samples
        :rtype: list(dict)
        """
        if len(sample_hash) == 32:  # MD5
            hash_type = "md5"
        elif len(sample_hash) == 40:  # SHA1
            hash_type = "sha1"
        elif len(sample_hash) == 64:  # SHA256
            hash_type = "sha256"
        else:
            raise UnknownHashTypeError("Sample hash has an unknown length.")

        return self._check_response(
            self.session.get(
                url="{}{}".format(
                    self.url,
                    self._sample_hash_endpoint.format(t=hash_type, h=sample_hash),
                ),
            )
        )

    def get_sample_iocs(self, sample_id):
        """
        Query IOCs for a given sample id.

        :param sample_id: ID of the sample
        :type sample_id: int
        :returns: Dictionary of IOCs
        :rtype: dict
        """
        return self._check_response(
            self.session.get(
                url="{}{}".format(
                    self.url, self._sample_iocs_endpoint.format(sample_id)
                ),
            )
        )

    def update_submission(self, submission_id):
        """
        Queries the current state of a submission.

        :param submission_id: ID of the submission
        :type submission_id: int
        :returns: Dictionary representing the submission
        :rtype: dict
        """
        return self._check_response(
            self.session.get(
                "{}{}".format(self.url, self._submission_endpoint.format(submission_id))
            )
        )

    def get_sample_analyses(self, sample_id):
        """
        Queries analyses about a sample using a given sample id.

        :param sample_id: ID of the sample
        :type sample_id: int
        :returns: List of analyses
        :rtype: list(dict)
        """
        return self._check_response(
            self.session.get(
                "{}{}".format(
                    self.url, self._sample_analyses_endpoint.format(sample_id)
                )
            )
        )
