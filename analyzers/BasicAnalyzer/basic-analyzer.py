#!/usr/bin/env python
# encoding: utf-8

from cortexutils.analyzer import Analyzer

# Define analyzer's class
class BasicExampleAnalyzer(Analyzer):
    # Analyzer's constructor
    def __init__(self):
        # Call the constructor of the super class
        Analyzer.__init__(self)

        # Read specific config options
        self.optional_prop = self.getParam('config.optional_prop', '')
        self.required_prop = self.getParam('config.required_prop', None, 'Error: Missing required_prop')

    # Override the report method. This is the analyzer's entry point
    def run(self):
        # Put your analyzer's logic here
        result = {}

        # This is just an example
        if self.data_type == 'ip':
            result['findings'] = ['1.1.1.1', '2.2.2.2', '3.3.3.3']
        elif self.data_type == 'domain':
            result['findings'] = ['domain1.com', 'domain2.com', 'domain3.com']
        else:
            return self.error('Unsupported observable data type')

        # Return the report
        return self.report(result)

    def summary(self, raw_report):
        return {
            'count': len(raw_report['findings'])
        }

    def artifacts(self, raw_report):
        result = []
        if 'findings' in raw_report:            
            for item in raw_report['findings']:
                result.append({'type': self.data_type, 'value': item})            

        return result
    
# Invoke the analyzer
if __name__ == '__main__':
    BasicExampleAnalyzer().run()