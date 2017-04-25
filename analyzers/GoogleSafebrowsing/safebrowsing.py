import json
import requests


class SearchTypeNotSupportedError(Exception):
    pass


class SafebrowsingClient:
    """Simple API to Google Safebrowsing and historic.

    :param key: API key for google safebrowsing
    :type key: str
    :param client_id: ClientId for Safebrowsing API
    :type client_id: str
    :param client_version: ClientVersion for Safebrowsing API. Default: 0.1
    :type client_version: str
    """
    def __init__(self, key, client_id, client_version='0.1'):
        self.api_key = key
        self.session = requests.Session()
        self.url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}'.format(key)
        self.client_id = client_id
        self.client_version = client_version

    def __prepare_body(self, search_value, search_type='url'):
        """
        Prepares the http body for querying safebrowsing api. Maybe the list need to get adjusted.

        :param search_value: value to search for
        :type search_value: str
        :param search_type: 'url' or 'ip'
        :type search_type: str
        :returns: http body as dict
        :rtype: dict
        """
        body = {
            'client': {
                'clientId': self.client_id,
                'clientVersion': self.client_version
            }
        }
        if search_type == 'url':
            data = {
                'threatTypes': [
                    'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'
                ],
                'platformTypes': ['ANY_PLATFORM', 'ALL_PLATFORMS', 'WINDOWS', 'LINUX', 'OSX', 'ANDROID', 'IOS'],
                'threatEntryTypes': ['URL']
            }
        elif search_type == 'ip':
            data = {
                'threatTypes': ['MALWARE'],
                'platformTypes': ['WINDOWS', 'LINUX', 'OSX'],
                'threatEntryTypes': ['IP_RANGE']
            }
        else:
            raise SearchTypeNotSupportedError('Currently supported search types are \'url\' and \'ip\'.')

        # TODO: Only found threatEntry 'url' in the docs. What to use for ip_range?
        data['threatEntries'] = [{'url': search_value}]
        body['threatInfo'] = data
        return body

    def __query_safebrowsing(self, search_value, search_type):
        """
        The actual query to safebrowsing api
        
        :param search_value: value to search for
        :type search_value: str
        :param search_type: 'url' or 'ip'
        :type search_type: str
        :return: Results
        :rtype: str
        """
        return json.loads(
                self.session.post(
                    self.url,
                    json=self.__prepare_body(
                        search_value=search_value,
                        search_type=search_type
                    )
                ).text
            )

    def query_url(self, url):
        return self.__query_safebrowsing(search_value=url, search_type='url')

    # TODO: Add another function for querying IPs
    def query_ip(self, ip):
        pass
