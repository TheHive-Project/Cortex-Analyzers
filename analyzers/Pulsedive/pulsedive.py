import requests

from cortexutils.analyzer import Analyzer


class PulsediveAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.url = 'https://pulsedive.com/api/'
        self.key = self.get_param('key', None, 'API-Key not given.')

    def _query(self, observable):
        request = self.url + 'info.php'
        result = requests.get(request, {
            'indicator': observable,
            'key': self.key
        }).json()

        if result.get('error', None) and result.get('error') != 'Indicator not found.':
            self.error(result.get('error'))
        return result

    def run(self):
        return self._query(self.get_data())


if __name__ == '__main__':
    PulsediveAnalyzer().run()
