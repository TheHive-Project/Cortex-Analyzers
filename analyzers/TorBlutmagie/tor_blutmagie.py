import requests
import pyfscache
import csv


class TorBlutmagieClient:
    """docstring for TorBlutmagieClient"""
    def __init__(self, cache_duration=3600, cache_root='/tmp/cortex/tor_project'):
        self.session = requests.Session()
        if cache_duration > 0:
            self.cache = pyfscache.FSCache(cache_root, seconds=cache_duration)
        self.url = 'http://torstatus.blutmagie.de/query_export.php/Tor_query_EXPORT.csv'

    def _get_raw_data(self):
        if self.cache is None:
            return self.session.get(self.url).text.encode('utf-8')
        else:
            try:
                return self.cache['raw_data']
            except KeyError:
                self.cache['raw_data'] = self.session.get(self.url).text.encode('utf-8')
                return self.cache['raw_data']

    def _get_data(self):
        return csv.DictReader(self._get_raw_data().splitlines(), delimiter=',')

    def _extract_fields(self, line):
        return {
            'hostname': line['Hostname'],
            'name': line['Router Name'],
            'country_code': line['Country Code'],
            'ip': line['IP Address'],
            'as_name': line['ASName'],
            'as_number': line['ASNumber']
        }

    def _get_node_from_domain(self, domain):
        results = []
        for line in self._get_data():
            if domain.lower() in line['Hostname'].lower():
                results.append(self._extract_fields(line))
        return results

    def _get_node_from_fqdn(self, fqdn):
        results = []
        for line in self._get_data():
            if fqdn.lower() == line['Hostname'].lower():
                results.append(self._extract_fields(line))
                break
        return results

    def _get_node_from_ip(self, ip):
        results = []
        for line in self._get_data():
            if ip == line['IP Address']:
                results.append(self._extract_fields(line))
                break
        return results

    def search_tor_node(self, data_type, data):
        results = []
        if data_type == 'ip':
            results = self._get_node_from_ip(data)
        elif data_type == 'fqdn':
            results = self._get_node_from_fqdn(data)
        elif data_type == 'domain':
            results = self._get_node_from_domain(data)
        else:
            pass
        return {"nodes": results}
