#!/usr/bin/env python3
# encoding: utf-8

import requests
from cortexutils.analyzer import Analyzer


class Threatcrowd(Analyzer):
    URI = "https://www.threatcrowd.org/searchApi/v2"

    def summary(self, raw):
        taxonomies = []

        level = None
        value = None

        if 'votes' in raw:
            r = raw.get('votes')
            value = r
            if r == 1:
                level = "safe"
            elif r == 0:
                level = "suspicious"
            elif r == -1:
                level = "malicious"
            else:
                value = "unknown"
                level = "info"
        else:
            value = "None"
            level = "info"

        taxonomies.append(self.build_taxonomy(level, "Threatcrowd", "votes", value))

        result = {"taxonomies": taxonomies}
        return result

    def run(self):
        Analyzer.run(self)

        if self.data_type == 'domain' or self.data_type == 'ip' or self.data_type == 'mail' or self.data_type == 'fqdn':
            threatcrowd_data_type = self.data_type if self.data_type != 'mail' else 'email'
            try:
                response = requests.get("{}/{}/report/".format(self.URI, threatcrowd_data_type),
                                        params = {threatcrowd_data_type: self.get_data()})
                self.report(response.json())
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    Threatcrowd().run()
