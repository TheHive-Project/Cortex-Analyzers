#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer

from passivetotal import analyzer as riqanalyzer
from _services import SERVICES


class IlluminateAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.property = self.get_param('config.property', None, 'RiskIQ Illuminate Analyzer object property is missing')
        self.username = self.get_param('config.username', None, 'RiskIQ Illuminate username is missing')
        self.api_key = self.get_param('config.api_key', None, 'RiskIQ Illuminate api_key is missing')
        self.days_back = self.get_param('config.days_back', None, 'RiskIQ Illuminate days_back is missing')
        riqanalyzer.init(username=self.username, api_key=self.api_key)
        riqanalyzer.set_date_range(days_back=self.days_back)
    
    def run(self):
        target = self.get_data()
        try:
            obj = riqanalyzer.get_object(target)
        except riqanalyzer.AnalyzerError as e:
            self.error('Cannot instantiate object for that type of input: {}'.format(e))
        try:
            value = getattr(obj, self.property)
            data = value.as_dict
        except riqanalyzer.AnalyzerError as e:
            self.error('Cannot get property "{0}": {1}'.format(self.property, e))
        self.report(data)

    def summary(self, raw):
        if self.property not in SERVICES:
            return []
        svc = SERVICES[self.property]
        return svc().summarize(raw)




if __name__ == '__main__':
    IlluminateAnalyzer().run()
    

