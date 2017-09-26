import requests


class TorProjectClient:
    """docstring for TorProjectClient"""
    def __init__(self):
        self.session = requests.Session()
        self.url = 'https://check.torproject.org/exit-addresses'

    def _get_raw_data(self):
        return self.session.get(self.url).text

    def query(self, ip):
        data = {}
        tmp = {}
        for line in self._get_raw_data().splitlines():
            params = line.split(' ')
            if params[0] == 'ExitNode':
                tmp['node'] = params[1]
            elif params[0] == 'ExitAddress':
                tmp['last_status'] = params[2] + 'T' + params[3] + '+0000'
                data[params[1]] = tmp
                tmp = {}
            else:
                pass
        return data.get(ip, {})
