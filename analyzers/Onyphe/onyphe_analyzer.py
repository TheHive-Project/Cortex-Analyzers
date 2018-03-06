#!/usr/bin/env python3

from cortexutils.analyzer import Analyzer
from onyphe_api import Onyphe


class OnypheAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            'config.service', None, 'Service parameter is missing')
        self.onyphe_key = self.get_param(
            'config.key', None, 'Missing Onyphe API key')
        self.onyphe_client = None
        self.polling_interval = self.get_param('config.polling_interval', 60)

    def summary(self, raw):
        taxonomies = []
        namespace = "Onyphe"
        if self.service == 'threats':
            output_data = {}
            for r in raw['threats']['results']:
                threatlist = r['threatlist']
                if threatlist not in output_data:
                    output_data[threatlist] = {
                        "dates": [],
                        "subnets": [],
                        "count": 0
                    }

                if r['seen_date'] not in output_data[threatlist]["dates"]:
                    output_data[threatlist]["dates"].append(r['seen_date'])
                    output_data[threatlist]["count"] += 1
                if r['subnet'] not in output_data[threatlist]["subnets"]:
                    output_data[threatlist]["subnets"].append(r['subnet'])
            for threatlist, threat_data in output_data.items():
                taxonomies.append(self.build_taxonomy(
                    'malicious', namespace, "Threat", "threatlist: {}, event count: {}".format(
                        threatlist, threat_data['count'])))

        if self.service == 'geolocate':
            location = raw['location']['results'][0]
            taxonomies.append(self.build_taxonomy(
                'info', namespace, "Geolocate", "country: {}, city: {}".format(
                    location["country_name"], location["city"])))

        if self.service == 'ports':
            output_data = {}
            for r in raw['ports']['results']:
                port = r['port']
                if port not in output_data:
                    output_data[port] = {
                        "dates": []
                    }
                if r['seen_date'] not in output_data[port]['dates']:
                    output_data[port]['dates'].append(r['seen_date'])
            for port_number, port_data in output_data.items():
                taxonomies.append(self.build_taxonomy(
                    'info', namespace, "Port", "port {} last seen {}".format(
                        port_number, port_data['dates'][0])))

        if self.service == 'reverse':
            output_data = {}
            for r in raw['reverses']['results']:
                reverse = r['domain']
                if reverse not in output_data:
                    output_data[reverse] = {
                        "dates": []
                    }

                if r['seen_date'] not in output_data[reverse]["dates"]:
                    output_data[reverse]["dates"].append(r['seen_date'])
            for reverse, reverse_data in output_data.items():
                taxonomies.append(self.build_taxonomy(
                    'info', namespace, "DNS Reverse", "name: {}, last_seen: {}".format(
                        reverse, reverse_data['dates'][0])))

        if self.service == 'forward':
            output_data = {}
            for r in raw['forwards']['results']:
                forwarder = r['forward']
                if forwarder not in output_data:
                    output_data[forwarder] = {
                        "dates": []
                    }

                if r['seen_date'] not in output_data[forwarder]["dates"]:
                    output_data[forwarder]["dates"].append(r['seen_date'])
            for forwarder, forward_data in output_data.items():
                taxonomies.append(self.build_taxonomy(
                    'info', namespace, "DNS Forwarder", "forwarder: {}, last_seen: {}".format(
                        forwarder, forward_data['dates'][0])))

        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)
        try:
            self.onyphe_client = Onyphe(self.onyphe_key)
            if self.service == 'threats':
                ip = self.get_param('data', None, 'Data is missing')
                results = {'threats': self.onyphe_client.threatlist(ip)}
                self.report(results)
            if self.service == 'ports':
                ip = self.get_param('data', None, 'Data is missing')
                results = {'ports': self.onyphe_client.synscan(ip)}
                self.report(results)
            if self.service == 'geolocate':
                ip = self.get_param('data', None, 'Data is missing')
                results = {'location': self.onyphe_client.geolocate(ip)}
                self.report(results)
            if self.service == 'reverse':
                ip = self.get_param('data', None, 'Data is missing')
                results = {'reverses': self.onyphe_client.reverse(ip)}
                self.report(results)
            if self.service == 'forward':
                ip = self.get_param('data', None, 'Data is missing')
                results = {'forwards': self.onyphe_client.forward(ip)}
                self.report(results)
        except Exception:
            pass


if __name__ == '__main__':
    OnypheAnalyzer().run()
