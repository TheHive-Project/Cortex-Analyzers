#!/usr/bin/env python
# encoding: utf-8

from cortexutils.analyzer import Analyzer

from pymisp import PyMISP

class MISPAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam('config.service', None, 'MISP service is missing')
        self.url = self.getParam('config.url', None, 'MISP url is missing')
        self.api_key = self.getParam('config.api_key', None, 'MISP api_key is missing')

    def summary(self, raw):
        result = {
            'service': self.service,
            'dataType': self.data_type
        }

        # search service
        if self.service == 'search':
            if 'response' in raw and raw['response']:
                result['results'] = len(raw['response'])
            else:
                result['results'] = 0

        return result

    def run(self):
        Analyzer.run(self)

        data = self.getData()

        try:
            # search service
            if self.service == 'search':
                misp = PyMISP(self.url, self.api_key)
                result = misp.search_all(data)

                events = []
                if 'response' in result:
                    # Trim the report to make it readable in a browser
                    # Remove null events

                    result['response'] = list(filter(lambda e: e != {'Event': None}, result['response']))
                    for e in result['response']:
                        if 'Event' in e and e['Event']:
                            event = e['Event']

                            # Remove attributes
                            if 'Attribute' in event:
                                del event['Attribute']
                            # Remove org
                            if 'Org' in event:
                                del event['Org']
                            # Remove related events
                            if 'RelatedEvent' in event:
                                del event['RelatedEvent']
                            # Remove shadow attributes
                            if 'ShadowAttribute' in event:
                                del event['ShadowAttribute']
                            # Remove sharing group
                            if 'SharingGroup' in event:
                                del event['SharingGroup']
                            # Remove sharing group
                            if 'Galaxy' in event:
                                del event['Galaxy']
                            # Replace tags by a string array
                            if 'Tag' in event:
                                tags = list((t['name'] for t in event['Tag']))
                                del event['Tag']
                                event['tags'] = tags
                            # Add url to the MISP event
                            if 'id' in event:
                                event['url'] = self.url + '/events/view/' + event['id']

                            events.append(event)

                self.report(events)
            else:
                self.error('Unknown MISP service')

        except Exception as e:
            self.unexpectedError(e)

if __name__ == '__main__':
    MISPAnalyzer().run()
