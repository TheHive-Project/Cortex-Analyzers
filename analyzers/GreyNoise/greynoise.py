#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests

from collections import defaultdict, OrderedDict
from cortexutils.analyzer import Analyzer


class GreyNoiseAnalyzer(Analyzer):
    """
    GreyNoise API docs: https://github.com/GreyNoise-Intelligence/api.greynoise.io
    """

    @staticmethod
    def _get_level(current_level, new_intention):
        """
        Map GreyNoise intentions to Cortex maliciousness levels.
        Accept a Cortex level and a GreyNoise intention, the return the more malicious of the two.

        :param current_level: A Cortex maliciousness level
            https://github.com/TheHive-Project/CortexDocs/blob/master/api/how-to-create-an-analyzer.md#output
        :param new_intention: An intention field value from a GreyNoise record
            https://github.com/GreyNoise-Intelligence/api.greynoise.io#v1queryip
        :return: The more malicious of the 2 submitted values as a Cortex maliciousness level
        """

        intention_level_map = OrderedDict([
            ('info', 'info'),
            ('benign', 'safe'),
            ('suspicious', 'suspicious'),
            ('malicious', 'malicious')
        ])
        levels = intention_level_map.values()

        new_level = intention_level_map.get(new_intention, 'info')
        new_index = levels.index(new_level)

        try:
            current_index = levels.index(current_level)
        except ValueError:  # There is no existing level
            current_index = -1

        return new_level if new_index > current_index else current_level

    def run(self):

        if self.data_type == "ip":
            api_key = self.get_param('config.key', None)
            url = 'https://api.greynoise.io/v1/query/ip'
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            data = {'ip': self.get_data()}
            if api_key:
                data['key'] = api_key
            response = requests.post(url, data=data, headers=headers)
            if not (200 <= response.status_code < 300):
                self.error('Unable to query GreyNoise API\n{}'.format(response.text))
            self.report(response.json())
        else:
            self.notSupported()

    def summary(self, raw):
        """
        Return one taxonomy summarizing the reported tags
            If there is only one tag, use it as the predicate
            If there are multiple tags, use "entries" as the predicate
            Use the total count as the value
            Use the most malicious level found


        Examples:


        Input
        {
            "name": SCANNER1,
            "intention": ""
        }
        Output
        GreyNoise:SCANNER1 = 1 (info)


        Input
        {
            "name": SCANNER1,
            "intention": "malicious"
        },
        {
            "name": SCANNER1,
            "intention": "benign"
        }
        Output
        GreyNoise:SCANNER1 = 2 (malicious)


        Input
        {
            "name": SCANNER1,
            "intention": ""
        },
        {
            "name": SCANNER1,
            "intention": "safe"
        },
        {
            "name": SCANNER2,
            "intention": ""
        }
        Output
        GreyNoise:entries = 3 (safe)
        """

        try:
            taxonomies = []
            if raw.get('records'):
                final_level = None
                taxonomy_data = defaultdict(int)
                for record in raw.get('records', []):
                    name = record.get('name', 'unknown')
                    intention = record.get('intention', 'unknown')
                    taxonomy_data[name] += 1
                    final_level = self._get_level(final_level, intention)

                if len(taxonomy_data) > 1:  # Multiple tags have been found
                    taxonomies.append(self.build_taxonomy(final_level, 'GreyNoise', 'entries', len(taxonomy_data)))
                else:  # There is only one tag found, possibly multiple times
                    for name, count in taxonomy_data.iteritems():
                        taxonomies.append(self.build_taxonomy(final_level, 'GreyNoise', name, count))

            else:
                taxonomies.append(self.build_taxonomy('info', 'GreyNoise', 'Records', 'None'))

            return {"taxonomies": taxonomies}

        except Exception as e:
            self.error('Summary failed\n{}'.format(e.message))


if __name__ == '__main__':
    GreyNoiseAnalyzer().run()
