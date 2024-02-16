#!/usr/bin/env python3
# encoding: utf-8
import requests
from cortexutils.analyzer import Analyzer


class PatrowlAnalyzer(Analyzer):
    """PatrowlAnalyzer Class definition."""

    def __init__(self):
        """Initialize the Analyzer."""
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Patrowl service is missing')
        self.url = self.get_param('config.url', None, 'Patrowl URL is missing').rstrip('/')
        self.api_key = self.get_param('config.api_key', None, 'Patrowl API Key is missing')        

    def summary(self, raw):
        """Parse, format and return scan summary."""
        taxonomies = []
        level = "info"
        namespace = "Patrowl"

        # getreport service
        if self.service == 'getreport':
            if 'risk_level' in raw and raw['risk_level']:
                risk_level = raw['risk_level']

                # Grade
                if risk_level['grade'] in ["A", "B"]:
                    level = "safe"
                else:
                    level = "suspicious"
                
                taxonomies.append(self.build_taxonomy(level, namespace, "Grade", risk_level['grade']))

                # Findings
                if risk_level['high'] > 0:
                    level = "malicious"
                elif risk_level['medium'] > 0 or risk_level['low'] > 0:
                    level = "suspicious"
                else:
                    level = "info"

                taxonomies.append(self.build_taxonomy(
                    level, namespace, "Findings", "{}/{}/{}/{}".format(
                        risk_level['high'],
                        risk_level['medium'],
                        risk_level['low'],
                        risk_level['info']
                    )))
        #todo: add_asset service

        return {"taxonomies": taxonomies}

    def run(self):
        """Run the analyzer."""
        try:
            if self.service == 'getreport':                
                service_url = '{}/assets/api/v1/details/{}'.format(
                    self.url, self.get_data())

                headers = {
                    'Authorization': 'token {}'.format(self.api_key)
                }
                
                response = requests.get(service_url, headers=headers)

                self.report(response.json())
            else:
                self.error('Unknown Patrowl service')

        except Exception as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    """Main function."""
    PatrowlAnalyzer().run()
