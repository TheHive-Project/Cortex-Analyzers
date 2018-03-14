import requests


class StopforumspamClient:

    _type_conversion = {'ip':'ip', 'mail':'email'}

    def __init__(self):
        self.client = requests.Session()

    def _set_payload(type, data):
        return {
            'json': True,
            'confidence': True,
            StopforumspamClient._type_conversion[type]: data
        }

    def get_data(self, datatype, data):
        result = {}
        params = StopforumspamClient._set_payload(datatype, data)
        response = self.client.get('https://api.stopforumspam.org/api', params=params)
        response.raise_for_status()
        report = response.json()
        print(report)
        if report['success']:
            result = report[StopforumspamClient._type_conversion[datatype]]
        else:
            pass
        return result
