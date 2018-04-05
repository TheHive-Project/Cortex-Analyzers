""" Class to interact with StopForumSpam's API

The API is documented at http://www.stopforumspam.com/usage

This client implementation supports only email address and IP addresses
reputation lookup. This class does not support submitting an entry to the
StopForumSpam service.

EXAMPLE USAGE:::

from stopforumspam_client import StopforumspamClient

client = StopforumspamClient()
response_ip = client.get_data('ip', '8.8.8.8')
print json.dumps(response_ip, sort_keys=False, indent=4)

response_email = client.get_data('mail', 'some.user@example.com')
print json.dumps(response_email, sort_keys=False, indent=4)
"""

import requests


class StopforumspamClient:

    _type_conversion = {'ip': 'ip', 'mail': 'email'}

    def __init__(self):
        self.client = requests.Session()

    def _set_payload(type, data):
        return {
            'json': True,
            'confidence': True,
            StopforumspamClient._type_conversion[type]: data
        }

    def data_conversion(self, data):
        if 'appears' in data:
            data['appears'] = (data['appears'] == 1)
        if 'torexit' in data:
            data['torexit'] = (data['torexit'] == 1)
        return data

    def get_data(self, datatype, data):
        """ Look for an IP address or an email address in the spammer database.

        :param datatype: Which type of data is to be looked up.
                         Allowed values are 'ip' or 'mail'.
        :param data: The value to be looked up through the API.
        :type datatype: str
        :type data: str
        :return: Data relative to the looked up artifact.
        :rtype: list
        """
        result = []
        params = StopforumspamClient._set_payload(datatype, data)
        response = self.client.get(
            'https://api.stopforumspam.org/api', params=params)
        response.raise_for_status()
        report = response.json()
        if report['success']:
            data = report[StopforumspamClient._type_conversion[datatype]]
            result.append(self.data_conversion(data))
        else:
            pass
        return result
