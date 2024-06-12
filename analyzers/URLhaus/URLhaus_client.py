import requests


BASEURL = 'https://urlhaus-api.abuse.ch/v1/'


class URLhausClient(object):
    @staticmethod
    def __request(endpoint, key, value) -> dict:
        results = requests.post(
            BASEURL + endpoint + '/',
            {key: value}
        ).json()

        if results['query_status'] in ['ok', 'no_results']:
            return results
        else:
            raise ValueError('Given value seems not to be valuid: <{}: {}>.'.format(key, value))

    @staticmethod
    def search_url(url: str) -> dict:
        return URLhausClient.__request(
            'url',
            'url',
            url
        )

    @staticmethod
    def search_host(host: str) -> dict:
        return URLhausClient.__request(
            'host',
            'host',
            host
        )

    @staticmethod
    def search_payload(payload_hash: str) -> dict:
        if len(payload_hash) == 32:
            return URLhausClient.__request(
                'payload',
                'md5_hash',
                payload_hash
            )
        elif len(payload_hash) == 64:
            return URLhausClient.__request(
                'payload',
                'sha256_hash',
                payload_hash
            )
        else:
            raise ValueError('Only sha256 and md5 hashes are allowed.')
