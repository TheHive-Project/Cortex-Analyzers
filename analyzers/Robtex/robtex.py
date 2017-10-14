import requests

from cortexutils.analyzer import Analyzer


class RobtexAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def query_ip(self):
        """
        Queries robtex api using an ip as parameter

        :return: Dictionary containing results
        :rtype: dict
        """
        return requests.get('https://freeapi.robtex.com/ipquery/{}'.format(self.get_data())).json()

    def query_rpdns(self):
        """
        Queries robtex reverse pdns-api using an ip as parameter

        :return: Dictionary containing results
        :rtype: dict
        """
        return requests.get('https://freeapi.robtex.com/pdns/reverse/{}'.format(self.get_data())).json()

    def query_fpdns(self):
        """
        Queries robtex forward pdns-api using an fqdn or domain as parameter

        :return: Dictionary containing results
        :rtype: dict
        """
        return requests.get('https://freeapi.robtex.com/pdns/forward/{}'.format(self.get_data())).json()

    def run(self):
        if self.get_param('config.service', None, 'Service not given') == 'ipquery'\
                and self.get_param('dataType', None) == 'ip':
            self.report(self.query_ip())
        elif self.get_param('config.service', None, 'Service not given') == 'rpdnsquery'\
                and self.get_param('dataType', None) == 'ip':
            self.report(self.query_rpdns())
        elif self.get_param('config.service', None, 'Service not given') == 'fpdnsquery' \
                and self.get_param('dataType', None) in ['fqdn', 'domain']:
            self.report(self.query_fpdns())
        else:
            self.error('Service or data type not supported by this analyzer.')


if __name__ == '__main__':
    RobtexAnalyzer().run()
