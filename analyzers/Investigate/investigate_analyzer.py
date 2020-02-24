#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.analyzer import Analyzer
from investigate import Investigate
from requests.exceptions import HTTPError

class InvestigateAnalyzer(Analyzer):
    STATUS_MAP = {-1: 'Blocked', 0: 'Unknown', 1: 'Whitelisted'}
    def __init__(self):
	    Analyzer.__init__(self)
	    self.service = self.get_param(
            'config.service', None, 'Service parameter is missing')

    def investigate(self, data):
        api = Investigate(self.get_param('config.key'))

        if self.service == 'categorization' and self.data_type in ['domain', 'fqdn']:
            response = api.categorization(data, labels=True)[data]
            response['name'] = data

        if self.service == 'sample' and self.data_type == 'hash':
            response = api.sample(data)

        return response

    def summary(self, raw):
        taxonomies = []
        namespace = 'Investigate'
        #Summary for domain categorization report
        if self.service == 'categorization':
            #Generate taxonomy of the domains current blocklist status
            predicate = 'Status'
            if 'status' not in raw:
                status = 0
            else:
                status = raw['status']

            if status == -1:
                level = 'malicious'
            elif status == 0:
                level = 'suspicious'
            elif status == 1:
                level = 'safe'

            taxonomies.append(self.build_taxonomy(level, namespace, predicate,
                              '{}'.format(self.STATUS_MAP[status])))
            
            #Generate taxonomy of the security categories associated with the domain
            level = 'info'
            predicate = 'Security Categories'
            if 'security_categories' not in raw:
                security_categories = []
            else:
                security_categories = raw['security_categories']
            
            display_str = ', '.join(security_categories) if security_categories else 'None'
            taxonomies.append(self.build_taxonomy(level, namespace, predicate,
                              '{}'.format(display_str)))

            #Generate taxonomy of the content categories associated with the domain
            predicate = 'Content Categories'
            if 'content_categories' not in raw:
                content_categories = []
            else:
                content_categories = raw['content_categories']
            
            display_str = ', '.join(content_categories) if content_categories else 'None'
            taxonomies.append(self.build_taxonomy(level, namespace, predicate,
                              '{}'.format(display_str)))


        #Summary for file hash lookup in sample database
        if self.service == 'sample':
            predicate = 'ThreatScore'
            if 'error' in raw:
                level = 'info'
                message = 'Hash not found'
            else:
                if raw['threatScore'] < 50:
                    level = 'safe'
                elif raw['threatScore'] >= 50 and raw['threatScore'] < 80:
                    level = 'suspicious'
                else:
                    level = 'malicious'
                message = '{}'.format(raw['threatScore']) 

            taxonomies.append(self.build_taxonomy(level, namespace, predicate, message))

        return {'taxonomies': taxonomies}

    def run(self):
        data = self.get_data()

        try:
            r = self.investigate(data)
            self.report(r)

        except HTTPError:
            self.error('An HTTP Error occurred. Check API key.')
        except Exception as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    InvestigateAnalyzer().run()
