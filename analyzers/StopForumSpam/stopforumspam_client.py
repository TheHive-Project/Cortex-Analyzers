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
        result = []
        params = StopforumspamClient._set_payload(datatype, data)
        response = self.client.get('https://api.stopforumspam.org/api', params=params)
        response.raise_for_status()
        report = response.json()
        if report['success']:
            data = report[StopforumspamClient._type_conversion[datatype]]
            result.append(self.data_conversion(data))
        else:
            pass
        return result
