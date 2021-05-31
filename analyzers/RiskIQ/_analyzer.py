#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer

from passivetotal import analyzer as riqanalyzer
from _services import SERVICES


class IlluminateAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self._property = self.get_param('config.property', None, 'RiskIQ Illuminate Analyzer object property is missing')
        self._username = self.get_param('config.username', None, 'RiskIQ Illuminate username is missing')
        self._api_key = self.get_param('config.api_key', None, 'RiskIQ Illuminate api_key is missing')
        self._days_back = self.get_param('config.days_back', None, 'RiskIQ Illuminate days_back is missing')
        riqanalyzer.init(username=self._username, api_key=self._api_key)
        riqanalyzer.set_date_range(days_back=self._days_back)
        if self._property not in SERVICES:
            self.error('Unknown property {}'.format(self._property))
        self._svc = SERVICES[self._property]()
    
    def run(self):
        ioc = self.get_data()
        try:
            ioc_obj = riqanalyzer.get_object(ioc)
        except riqanalyzer.AnalyzerError as e:
            self.error('Cannot instantiate object for that type of input: {}'.format(e))
        try:
            value = getattr(ioc_obj, self._property)
        except AttributeError as e:
            self.error('Unknown property {}'.format(self._property))
        except riqanalyzer.AnalyzerError as e:
            self.error('API error while getting property "{0}": {1}'.format(self._property, e))
        try:
            data = value.as_dict
        except Exception as e:
            self.error('Cannot transform property "{0}" to dictionary: {1}'.format(self._property, e))
        data = self._svc.transform(data)
        self.report(data)

    def summary(self, raw):
        return self._svc.summarize(raw)




if __name__ == '__main__':
    IlluminateAnalyzer().run()
    

