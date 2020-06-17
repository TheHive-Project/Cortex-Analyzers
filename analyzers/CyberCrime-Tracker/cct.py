#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from cortexutils.analyzer import Analyzer
from cybercrimetracker.cybercrimeTrackerAPI import cybercrimeTrackerAPI


class CyberCrimeTrackerAnalyzer(Analyzer):
    """
    This analyzer searches 
    http://cybercrime-tracker.net
    for possible c2 servers.
    """

    def __init__(self):
        Analyzer.__init__(self)

    def summary(self, raw):
        level = 'info'
        namespace = 'CCT'
        predicate = 'C2 Search'

        hit_count = len(raw.get('results', []))
        value = "{} hits".format(hit_count)
        if hit_count == 1:
            value = value[:-2] + ""

        if hit_count > 0:
            level = 'malicious'

        taxonomies = []
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {
            "taxonomies": taxonomies
        }

    def run(self):
        observable = self.get_data()
        limit = 40
        offset = 0

        results = []

        try:
            while True:
                new_results = cybercrimeTrackerAPI().search(query=observable, offset=offset, limit=limit)
                results.extend(new_results)

                current_hit_count = len(new_results)
                no_more_results = current_hit_count < limit
                if no_more_results:
                    break
                offset += limit

            self.report({
                'results': results
            })
        except Exception:
            self.error('An error occurred while scraping cybercrime-tracker.')


if __name__ == '__main__':
    CyberCrimeTrackerAnalyzer().run()
