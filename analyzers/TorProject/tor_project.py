import requests
from datetime import datetime, timedelta
from dateutil.parser import parse
import pytz
import pyfscache


class TorProjectClient:
    """docstring for TorProjectClient"""
    def __init__(self, ttl, cache_duration, cache_root):
        self.session = requests.Session()
        self.delta = timedelta(seconds=ttl)
        self.cache = pyfscache.FSCache(cache_root, seconds=cache_duration)
        self.url = 'https://check.torproject.org/exit-addresses'

    def _get_raw_data(self):
        try:
            return self.cache['raw_data']
        except KeyError:
            self.cache['raw_data'] = self.session.get(self.url).text
            return self.cache['raw_data']

    def query(self, ip):
        data = {}
        tmp = {}
        present = datetime.utcnow().replace(tzinfo=pytz.utc)
        for line in self._get_raw_data().splitlines():
            params = line.split(' ')
            if params[0] == 'ExitNode':
                tmp['node'] = params[1]
            elif params[0] == 'ExitAddress':
                tmp['last_status'] = params[2] + 'T' + params[3] + '+0000'
                last_status = parse(tmp['last_status'])
                if (present - last_status) < self.delta:
                    data[params[1]] = tmp
                tmp = {}
            else:
                pass
        return data.get(ip, {})
