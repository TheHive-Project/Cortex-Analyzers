#!/usr/bin/env python3
# encoding: utf-8


import re
import requests
from cortexutils.analyzer import Analyzer


class URLCategoryAnalyzer(Analyzer):

    def summary(self, raw):

        taxonomies = []

        if 'category' in raw:
            r = raw.get('category')
            value = "{}".format(r)
            if r in self.get_param('config.malicious_categories', []):
                level = "malicious"
            elif r in self.get_param('config.suspicious_categories', []):
                level = "suspicious"
            elif r == "Not Rated":
                level = "safe"
            else:
                level = "info"

            taxonomies.append(self.build_taxonomy(level, "Fortiguard", "URLCat", value))

        result = {"taxonomies": taxonomies}
        return result

    def run(self):
        Analyzer.run(self)

        if self.data_type == 'domain' or self.data_type == 'url' or self.data_type == 'fqdn':
            try:
                pattern = re.compile("(?:Category: )([-\w\s]+)")
                baseurl = 'https://www.fortiguard.com/webfilter?q='
                url = baseurl + self.get_data()
                req = requests.get(url)
                category_match = re.search(pattern, req.text, flags=0)
                self.report({
                    'category': category_match.group(1)
                })
            except ValueError as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    URLCategoryAnalyzer().run()
